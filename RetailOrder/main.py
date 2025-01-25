from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import User, Product, Order, OrderDetail
from database import get_db, Base, engine
from pydantic import BaseModel

app = FastAPI(
    title="Retail Ordering System",
    description="An API to manage users, products, and orders with role-based access control",
    version="1.0.0",
)

Base.metadata.create_all(bind=engine)

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if not username or not role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate token")

@app.get("/", tags=["Root"])
def read_root():
    return {"message": "Retail Ordering System is running!"}

class RegisterUserRequest(BaseModel):
    username: str
    password: str
    role: str = "customer"

@app.post("/register", tags=["Users"], summary="Register a new user")
def register_user(request: RegisterUserRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )
    hashed_password = get_password_hash(request.password)
    new_user = User(username=request.username, password_hash=hashed_password, role=request.role)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

# Authentication
@app.post("/token", tags=["Authentication"], summary="Generate an access token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/products", tags=["Products"], summary="List all products")
def list_products(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    return db.query(Product).offset(skip).limit(limit).all()

@app.post("/api/products", tags=["Products"], summary="Add a new product")
def add_product(name: str, price: float, stock: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    new_product = Product(name=name, price=price, stock=stock)
    db.add(new_product)
    db.commit()
    return {"message": "Product added successfully"}

@app.put("/api/products/{product_id}", tags=["Products"], summary="Update an existing product")
def update_product(product_id: int, name: str = None, price: float = None, stock: int = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    if name is not None:
        product.name = name
    if price is not None:
        product.price = price
    if stock is not None:
        product.stock = stock
    db.commit()
    return {"message": "Product updated successfully"}

@app.delete("/api/products/{product_id}", tags=["Products"], summary="Delete a product")
def delete_product(product_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    db.delete(product)
    db.commit()
    return {"message": "Product deleted successfully"}

# Order Management
@app.get("/api/orders", tags=["Orders"], summary="List all orders")
def list_all_orders(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    orders = db.query(Order).offset(skip).limit(limit).all()
    return [
        {
            "id": order.id,
            "user_id": order.user_id,
            "total_price": order.total_price,
            "status": order.status,
            "order_details": [
                {"product_id": detail.product_id, "quantity": detail.quantity}
                for detail in order.order_details
            ],
        }
        for order in orders
    ]


# noinspection PyTypeChecker
@app.post("/api/orders", tags=["Orders"], summary="Create a new order")
def create_order(order_details: list[dict], db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "customer":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    total_price = 0
    new_order = Order(user_id=user.id, total_price=0, status="pending")
    db.add(new_order)
    db.commit()
    for detail in order_details:
        product = db.query(Product).filter(Product.id == detail["product_id"]).first()
        if not product:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Product with ID {detail['product_id']} not found")
        if product.stock < detail["quantity"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Insufficient stock for product ID {detail['product_id']}")
        order_detail = OrderDetail(order_id=new_order.id, product_id=product.id, quantity=detail["quantity"], price=product.price)
        db.add(order_detail)
        product.stock -= detail["quantity"]
        total_price += product.price * detail["quantity"]
    new_order.total_price = total_price
    db.commit()
    return {"message": "Order created successfully", "order_id": new_order.id}

@app.put("/api/orders/{order_id}/status", tags=["Orders"], summary="Update the status of an order")
def update_order_status(order_id: int, status1: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status1.HTTP_403_FORBIDDEN, detail="Not authorized")
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=status1.HTTP_404_NOT_FOUND, detail="Order not found")
    order.status = status1
    db.commit()
    return {"message": "Order status updated successfully"}

@app.get("/api/orders/{customer_id}", tags=["Orders"], summary="Get customer-specific orders")
def get_customer_orders(customer_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "customer" and user.id != customer_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    orders = db.query(Order).filter(Order.user_id == customer_id).all()
    return [
        {
            "id": order.id,
            "total_price": order.total_price,
            "status": order.status,
            "order_details": [
                {"product_id": detail.product_id, "quantity": detail.quantity}
                for detail in order.order_details
            ],
        }
        for order in orders
    ]

@app.get("/api/orders/{order_id}/status", tags=["Orders"], summary="Get order status")
def get_order_status(order_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    if user.role != "admin" and user.id != order.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return {"order_id": order.id, "status": order.status}
