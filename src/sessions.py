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

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at

    def idle_time(self) -> timedelta:
        return datetime.now() - self.last_used_at

    def touch(self):
        self.last_used_at = datetime.now()


class SessionsStorage:
    """SessionsStorage creates, stores and process all the sessions"""

    def __init__(self):
        self.sessions = {}
        self.lock = threading.RLock()

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

            profile_dir = None
            if profile_key:
                digest = hashlib.sha256(profile_key.encode()).hexdigest()
                profile_dir = os.path.join('/config/kani-profiles', digest)
                os.makedirs(profile_dir, exist_ok=True)
            driver = utils.get_webdriver(proxy, profile_dir) if profile_dir \
                else utils.get_webdriver(proxy)
            created_at = datetime.now()
            session = Session(session_id, driver, created_at, created_at)

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

    @staticmethod
    def _close(session: Session):
        with session.lock:
            if utils.PLATFORM_VERSION == "nt":
                session.driver.close()
            session.driver.quit()

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
               profile_key: Optional[str] = None):
        with self.lock:
            session, fresh = self.get(session_id, ttl, profile_key)
            session.lock.acquire()
        try:
            yield session, fresh
        finally:
            session.touch()
            session.lock.release()

    def session_ids(self) -> list[str]:
        with self.lock:
            return list(self.sessions.keys())
