#!/usr/bin/env python3
"""API session expiration module
"""
import os
from .session_auth import SessionAuth
from flask import request
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """Session expiration.
    """

    def __init__(self) -> None:
        """Initializes a new SessionExpAuth.
        """
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Creates a Session ID for user_id
        """
        session_id = super().create_session(user_id)
        if type(session_id) != str:
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """Returns User ID based on Session ID
        """
        if session_id in self.user_id_by_session_id:
            session_dict = self.user_id_by_session_id[session_id]
            if self.session_duration <= 0:
                return session_dict['user_id']
            
            if 'created_at' not in session_dict:
                return None
            
            strt_time = datetime.now()
            session_elapsed = timedelta(seconds=self.session_duration)
            end_time = session_dict['created_at'] + session_elapsed
            if end_time < strt_time:
                return None
            return session_dict['user_id']
