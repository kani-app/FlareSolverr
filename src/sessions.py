import logging
import threading
import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid1

from selenium.webdriver.chrome.webdriver import WebDriver

import utils


@dataclass
class Session:
    session_id: str
    driver: WebDriver
    created_at: datetime
    last_used_at: datetime
    lock: threading.RLock = field(default_factory=threading.RLock)
    in_use: bool = False
    profile_dir: Optional[str] = None

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at

    def idle_time(self) -> timedelta:
        return datetime.now() - self.last_used_at

    def touch(self):
        self.last_used_at = datetime.now()


MAX_SESSIONS = max(1, int(os.environ.get('MAX_SESSIONS', '4')))

PROFILES_ROOT = '/config/kani-profiles'

# Chrome's profile lock. The lock names the host and pid that took it, and a
# host that differs from ours reads as the profile being open on another
# computer: Chrome refuses to start and chromedriver times out. /config outlives
# the container while the hostname (the container id) does not, so every
# recreate strands the lock of any browser that was not shut down cleanly.
PROFILE_LOCK_FILES = ('SingletonLock', 'SingletonSocket', 'SingletonCookie')


class SessionsStorage:
    """SessionsStorage creates, stores and process all the sessions"""

    def __init__(self):
        self.sessions = {}
        self.lock = threading.RLock()
        # Profile directories a browser launched by this process may still hold,
        # including one whose session is gone but whose close has not finished.
        self._held_profiles = set()

    def _evict_until_under_cap(self):
        """Each live session holds a browser, so an uncapped store grows with the
        number of callers. Evicts least-recently-used sessions that are not
        mid-capture; a busy store may briefly exceed the cap rather than block."""
        while len(self.sessions) >= MAX_SESSIONS:
            idle = [s for s in self.sessions.values() if not s.in_use]
            if not idle:
                logging.warning(
                    'session cap %d reached with every session busy; '
                    'allowing an extra session', MAX_SESSIONS)
                return
            victim = min(idle, key=lambda s: s.last_used_at)
            logging.info('evicting least-recently-used session %s to stay under '
                         'the cap of %d', victim.session_id, MAX_SESSIONS)
            self.sessions.pop(victim.session_id, None)
            threading.Thread(target=self._close, args=(victim,), daemon=True).start()

    def _release_stale_profile_lock(self, profile_dir: str):
        """Only this process launches browsers on these profiles, so a lock on a
        directory none of its browsers holds is stale whatever host it names."""
        if profile_dir in self._held_profiles:
            return
        for name in PROFILE_LOCK_FILES:
            path = os.path.join(profile_dir, name)
            if os.path.lexists(path):
                logging.info('removing stale Chrome profile lock %s -> %s',
                             path, os.readlink(path) if os.path.islink(path) else '')
                os.remove(path)

    def create(self, session_id: Optional[str] = None, proxy: Optional[dict] = None,
               force_new: Optional[bool] = False,
               profile_key: Optional[str] = None) -> Tuple[Session, bool]:
        """create creates new instance of WebDriver if necessary,
        assign defined (or newly generated) session_id to the instance
        and returns the session object. If a new session has been created
        second argument is set to True.

        Note: The function is idempotent, so in case if session_id
        already exists in the storage a new instance of WebDriver won't be created
        and existing session will be returned. Second argument defines if 
        new session has been created (True) or an existing one was used (False).
        """
        session_id = session_id or str(uuid1())

        with self.lock:
            if force_new:
                self.destroy(session_id)

            if self.exists(session_id):
                return self.sessions[session_id], False

            self._evict_until_under_cap()

            profile_dir = None
            if profile_key:
                digest = hashlib.sha256(profile_key.encode()).hexdigest()
                profile_dir = os.path.join(PROFILES_ROOT, digest)
                os.makedirs(profile_dir, exist_ok=True)
                self._release_stale_profile_lock(profile_dir)
            driver = utils.get_webdriver(proxy, profile_dir) if profile_dir \
                else utils.get_webdriver(proxy)
            if profile_dir:
                self._held_profiles.add(profile_dir)
            created_at = datetime.now()
            session = Session(session_id, driver, created_at, created_at,
                              profile_dir=profile_dir)

            self.sessions[session_id] = session

            return session, True

    def exists(self, session_id: str) -> bool:
        with self.lock:
            return session_id in self.sessions

    def destroy(self, session_id: str) -> bool:
        """destroy closes the driver instance and removes session from the storage.
        The function is noop if session_id doesn't exist.
        The function returns True if session was found and destroyed,
        and False if session_id wasn't found.
        """
        with self.lock:
            if not self.exists(session_id):
                return False

            session = self.sessions.pop(session_id)
            self._close(session)
            return True

    def invalidate(self, session_id: str) -> bool:
        with self.lock:
            session = self.sessions.pop(session_id, None)
        if session is None:
            return False
        threading.Thread(target=self._close, args=(session,), daemon=True).start()
        return True

    def _close(self, session: Session):
        try:
            with session.lock:
                if utils.PLATFORM_VERSION == "nt":
                    session.driver.close()
                session.driver.quit()
        finally:
            if session.profile_dir:
                with self.lock:
                    self._held_profiles.discard(session.profile_dir)

    def get(self, session_id: str, ttl: Optional[timedelta] = None,
            profile_key: Optional[str] = None) -> Tuple[Session, bool]:
        session, fresh = self.create(session_id, profile_key=profile_key)

        if ttl is not None and not fresh and session.idle_time() > ttl:
            logging.debug(f'session\'s idle time has expired, so the session is recreated (session_id={session_id})')
            session, fresh = self.create(session_id, force_new=True, profile_key=profile_key)

        session.touch()

        return session, fresh

    @contextmanager
    def locked(self, session_id: str, ttl: Optional[timedelta] = None,
               profile_key: Optional[str] = None,
               timeout: Optional[float] = None):
        with self.lock:
            session, fresh = self.get(session_id, ttl, profile_key)
            acquired = session.lock.acquire(timeout=timeout) if timeout is not None \
                else session.lock.acquire()
        if not acquired:
            raise TimeoutError(f'Timeout waiting for session {session_id}.')
        session.in_use = True
        try:
            yield session, fresh
        finally:
            session.in_use = False
            session.touch()
            session.lock.release()

    def session_ids(self) -> list[str]:
        with self.lock:
            return list(self.sessions.keys())
