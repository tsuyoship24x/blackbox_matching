class Config:
    SECRET_KEY = 'change-this-secret-key'  # TODO: override in production
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False