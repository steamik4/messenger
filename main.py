import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

# ------------------------------------------------------------------------------
# 1. КОНФИГУРАЦИЯ И БАЗА ДАННЫХ (SQLAlchemy + SQLite)
# ------------------------------------------------------------------------------
DATABASE_URL = "sqlite:///./messenger.db"
SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"  # Секретный ключ для JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------------------------------------------------------
# 2. МОДЕЛИ БАЗЫ ДАННЫХ
# ------------------------------------------------------------------------------
class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)


class MessageDB(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    text = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("UserDB", foreign_keys=[sender_id])
    recipient = relationship("UserDB", foreign_keys=[recipient_id])


Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------------------
# 3. АВТОРИЗАЦИЯ И ХЭШИРОВАНИЕ ПАРОЛЕЙ (JWT & Bcrypt)
# ------------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> UserDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось валидировать токен",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = (
        db.query(UserDB).filter(UserDB.username == username).first()
    )
    if user is None:
        raise credentials_exception
    return user


# ------------------------------------------------------------------------------
# 4. SCHEMAS (Pydantic для валидации входных/выходных данных)
# ------------------------------------------------------------------------------
class UserCreate(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class MessageOut(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    text: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ------------------------------------------------------------------------------
# 5. МЕНЕДЖЕР ПОДКЛЮЧЕНИЙ WEBSOCKET (Адресная доставка)
# ------------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        # Храним активные соединения: user_id -> WebSocket
        self.active_connections: Dict[int, WebSocket] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: str, user_id: int):
        # Если пользователь онлайн — сразу отправляем ему сообщение в WebSocket
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)


manager = ConnectionManager()

# ------------------------------------------------------------------------------
# 6. FASTAPI ПРИЛОЖЕНИЕ И ЭНДПОИНТЫ
# ------------------------------------------------------------------------------
app = FastAPI(title="Telegram-like Messenger API")


@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = (
        db.query(UserDB).filter(UserDB.username == user.username).first()
    )
    if db_user:
        raise HTTPException(
            status_code=400, detail="Имя пользователя уже занято"
        )

    hashed_pwd = get_password_hash(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = (
        db.query(UserDB).filter(UserDB.username == form_data.username).first()
    )
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: UserDB = Depends(get_current_user)):
    return current_user


@app.get("/users", response_model=List[UserOut])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user),
):
    # Получить список всех пользователей для создания чата
    return db.query(UserDB).filter(UserDB.id != current_user.id).all()


@app.get("/messages/{recipient_id}", response_model=List[MessageOut])
def get_chat_history(
    recipient_id: int,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user),
):
    # Получение истории переписки между текущим пользователем и recipient_id
    messages = (
        db.query(MessageDB)
        .filter(
            ((MessageDB.sender_id == current_user.id) & (MessageDB.recipient_id == recipient_id))
            | ((MessageDB.sender_id == recipient_id) & (MessageDB.recipient_id == current_user.id))
        )
        .order_by(MessageDB.timestamp.asc())
        .all()
    )
    return messages


# ------------------------------------------------------------------------------
# 7. WEBSOCKET ЭНДПОИНТ (Отправка и получение сообщений)
# ------------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    db: Session = Depends(get_db),
):
    # Проверка JWT-токена при подключении WebSocket
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(user.id, websocket)

    try:
        while True:
            # Ждем JSON формат сообщения: {"recipient_id": 2, "text": "Привет!"}
            data = await websocket.receive_json()
            recipient_id = data.get("recipient_id")
            text = data.get("text")

            if recipient_id and text:
                # 1. Сохраняем сообщение в БД
                db_message = MessageDB(
                    sender_id=user.id,
                    recipient_id=recipient_id,
                    text=text,
                )
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Формируем JSON ответ
                message_payload = f"{user.username}: {text}"

                # 2. Отправляем адресату, если он онлайн
                await manager.send_personal_message(message_payload, recipient_id)

                # 3. Эхо-ответ отправителю для подтверждения доставки
                await manager.send_personal_message(f"Вы: {text}", user.id)

    except WebSocketDisconnect:
        manager.disconnect(user.id)