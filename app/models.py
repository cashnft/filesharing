from app import db
from datetime import datetime, timedelta
import uuid
import secrets

class File(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)
    password_protected = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(255), nullable=True)
    
    #Expiration settings
    expires_at = db.Column(db.DateTime, nullable=True)
    max_downloads = db.Column(db.Integer, nullable=True)
    download_count = db.Column(db.Integer, default=0)
    
    #Access key for sharing
    access_key = db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def is_expired(self):
        # Check if file has expired
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        if self.max_downloads and self.download_count >= self.max_downloads:
            return True
        return False
        
    @classmethod
    def create_file(cls, filename, file_path, salt, iv, password_protected=False, 
                   password_hash=None, expire_days=7, max_downloads=None):
        """Create a new file entry with the specified parameters"""
        expires_at = datetime.utcnow() + timedelta(days=expire_days) if expire_days else None
        
        file = cls(
            filename=filename,
            file_path=file_path,
            salt=salt,
            iv=iv,
            password_protected=password_protected,
            password_hash=password_hash,
            expires_at=expires_at,
            max_downloads=max_downloads
        )
        
        db.session.add(file)
        db.session.commit()
        return file