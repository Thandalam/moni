# pylint: disable=logging-format-interpolation
"""The above code is importing the necessary libraries for the program to run.
"""
import random
import string
import datetime as dt
from typing import Dict, List, Optional
from dotenv import load_dotenv
from fastapi.logger import logger
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import  Form, Request, HTTPException, status, Depends, Response, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2, OAuth2PasswordRequestForm
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security.utils import get_authorization_scheme_param
from passlib.context import CryptContext
from jose import JWTError, jwt
from config import SETTING
from models import User

load_dotenv()

APP = APIRouter(tags=["creating shipment api's"])

APP.mount("/static", StaticFiles(directory="static"), name="static")

TEMPLATES = Jinja2Templates(directory="templates")

CLIENT = SETTING.CLIENT

SIGNUP_COLLECTION = SETTING.SIGNUP_COLLECTION



PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    """Function to change plain password to Hash"""
    return PWD_CONTEXT.hash(password)

def verify_password(password: str, hashed_password: str):
    """Function to verify hased password"""
    return PWD_CONTEXT.verify(password, hashed_password)


def get_user(email: str) -> User:
     
    # Return user data from the specified MongoDB collection based on the user's email address.

    user = SIGNUP_COLLECTION.find_one({"Email":email})
    if user:
        return user
    return None
# #########This is likely a Python class that extends the OAuth2 class, which is a class provided by the fastapi.security module in FastAPI.

# Based on the name of the class, it seems to be a custom implementation of an OAuth2 authentication scheme that involves passing the access token as a cookie, rather than in the Authorization header of the HTTP request.

# The OAuth2 class is a general-purpose OAuth2 class that can be used to implement various OAuth2 flows, such as the Authorization Code flow or the Implicit flow.

# Without more context, it's difficult to say exactly how this class works or what its methods and attributes are. However, it is likely that the OAuth2PasswordBearerWithCookie class defines additional methods or overrides existing methods from the OAuth2 class to handle the specific behavior of passing the access token as a cookie.




# Regenerate response###########

class OAuth2PasswordBearerWithCookie(OAuth2):
#     The constructor method __init__() takes in several parameters:

# tokenUrl: a required string parameter that specifies the URL for token authentication.
# scheme_name: an optional string parameter that specifies the name of the scheme (if not specified, the default name "OAuth2" is used).
# scopes: an optional dictionary parameter that specifies the scopes for the authentication token.
# description: an optional string parameter that provides a description of the security scheme.
# auto_error: a boolean parameter that determines whether an HTTPException should be raised if the authentication fails.
# In the __init__() method, the OAuthFlowsModel class is used to create a password flow with the tokenUrl and scopes parameters, which is then passed to the parent constructor of the OAuth2 class along with the other parameters.

# The __call__() method is an asynchronous method that takes a Request object as a parameter and returns an optional string. It is called by FastAPI to authenticate the request using this security scheme. The method likely handles the actual authentication of the request by checking the token in the request header or cookie, and returns the token string if authentication is successful. If authentication fails, the method returns None.
   
    def __init__(self, tokenUrl: str, scheme_name: Optional[str] = None, scopes: Optional[Dict[str, str]] = None, description: Optional[str] = None, auto_error: bool = True):
        
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        
        authorization: str = request.cookies.get(SETTING.COOKIE_NAME)
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                #redirect to login page
            return None
        return param

OAUTH2_SCHEME = OAuth2PasswordBearerWithCookie(tokenUrl="token")
# """
# An instance of the OAuth2PasswordBearerWithCookie class that can be used to authenticate
# requests that require an OAuth2 bearer token and/or an HTTP cookie.

# Args:
#     tokenUrl (str, optional): The URL of the token endpoint. Defaults to "token".
#     scheme_name (str, optional): The name of the authentication scheme. Defaults to "bearer".
#     scopes (dict, optional): A dictionary of OAuth2 scopes that the client is authorized to use.
#     description (str, optional): A description of the authentication scheme.
#     auto_error (bool, optional): Whether to automatically return an HTTP 401 response
#         if authentication fails.

# Returns:
#     OAuth2PasswordBearerWithCookie: An instance of the OAuth2PasswordBearerWithCookie class.
# """

def create_access_token(data: Dict) -> str:
    # """
    # Create a JSON Web Token (JWT) access token from given dictionary of data.

    # Parameters:
    #     data (Dict): A dictionary of data to encode in the access token.

    # Args:
    #     data (Dict): A dictionary of data to include in the access token payload.

    # Returns:
    #     str: The encoded JWT access token.

    # Raises:
    #     ValueError: If the `data` argument is empty or not a dictionary.
    # """
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=SETTING.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        SETTING.SECRET_KEY,
        algorithm=SETTING.ALGORITHM
    )
    return encoded_jwt

def authenticate_user(username: str, plain_password: str) -> User:
    # """
    # Authenticates a user with the given username and plain-text password.

    # Parameters:
    #     username (str): The username of the user to authenticate.
    #     plain_password (str): The plain-text password of the user to authenticate.

    # Returns:
    #     Union[User, bool]: The authenticated user object as a `User` instance, or `False`
    #     if the user is not found or the password is incorrect.

    # Raises:
    #     Union[bool, User]: If authentication fails, returns False. Otherwise,
    #     returns a User object for the authenticated user.
    # """
    user = get_user(username)
    if not user:
        return False
    if not verify_password(plain_password, user['Password']):
        return False
    return user

def decode_token(token: str) -> User:
    # """
    # Decode a JWT token and return the associated user,
    # or redirect to the login page if the token is invalid.

    # Parameters:
    #     token (str): The JWT token to decode.

    # Returns:
    #     Union[User, RedirectResponse]: If the token is valid,
    #     returns a User object for the associated user. Otherwise,
    #     returns a RedirectResponse object that redirects to the login page.

    # credentials_exception = HTTPException(
    #     status_code=status.HTTP_401_UNAUTHORIZED,
    #     detail="Could not validate credentials."
    # )
    # """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials."
    )
    token = str(token).replace("Bearer", "").strip()

    try:
        payload = jwt.decode(token, SETTING.SECRET_KEY, algorithms=[SETTING.ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    user = get_user(username)
    return user

def get_current_user_from_token(token: str = Depends(OAUTH2_SCHEME)) -> User:
    # """
    # Returns the authenticated user by decoding the provided JWT token

    # Args:
    # token (str, optional): The JWT token to decode. Defaults to Depends(OAUTH2_SCHEME).

    # Returns:
    #     User: The authenticated user.

    # Raises:
    #     HTTPException: If the provided token is invalid or the user cannot be found.
    # """
    user = decode_token(token)
    return user

def get_current_user_from_cookie(request: Request) -> User:
    # """
    # Get the current user from a cookie in a request.

    # Parameters:
    # - request (Request): The HTTP request containing the access token cookie.

    # Returns:
    # - user (User): The User object corresponding to the access token cookie.

    # """
    token = request.cookies.get(SETTING.COOKIE_NAME)
    user = decode_token(token)
    return user




@APP.post("token")
def login_for_access_token(response: Response,\
        form_data: OAuth2PasswordRequestForm = Depends()) -> Dict[str, str]:
    # """
    # Endpoint to handle user authentication and access token generation.

    # Args:
    #     response (fastapi.Response): The HTTP response object.
    #     form_data (OAuth2PasswordRequestForm): The OAuth2 password request form data.

    # Returns:
    #     A dictionary containing the access token and token type.
    # """
    # Authenticate the user with the provided credentials
    user = authenticate_user(form_data.login_user, form_data.login_password)
    if not user:
        # If the user is not authenticated, raise an HTTPException with 401 status code
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, \
            detail="Incorrect username or password")

    # Create an access token for the authenticated user
    access_token = create_access_token(data={"username": user["Email"]})

    # Set an HttpOnly cookie in the response. `httponly=True` prevents
    # JavaScript from reading the cookie.
    response.set_cookie(
        key=SETTING.COOKIE_NAME,
        value=f"Bearer {access_token}",
        httponly=True
    )
    # Return the access token and token type in a dictionary
    return {SETTING.COOKIE_NAME: access_token, "token_type": "bearer"}

class LoginForm:
    # """
    # A class that represents a login form and provides methods to load and validate form data.

    # Attributes:
    #     request (Request): A `Request` object representing the incoming HTTP request.
    #     errors (List): A list of error messages that can be returned during form validation.
    #     login_user (Optional[str]): A string representing the user's login email,
    #     or `None` if not specified.
    #     login_password (Optional[str]): A string representing the user's login password,
    #     or `None` if not specified.
    # """

    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.login_user: Optional[str] = None
        self.login_password: Optional[str] = None

    async def load_data(self):
        # """
        # Asynchronously loads form data from the incoming request
        # and sets the `login_user` and `login_password`
        # attributes of the `LoginForm` object.

        # Args:
        #     self (LoginForm): The `LoginForm` object to load data into.

        # Returns:
        #     None.
        # """
        form = await self.request.form()
        self.login_user = form.get("login_user")
        self.login_password = form.get("login_password")

    async def is_valid(self):
        # """
        # Asynchronously validates the `LoginForm` object's `login_user`
        # and `login_password` attributes and
        # returns a boolean indicating whether the attributes are valid.

        # If either the `login_user` or `login_password` attributes are invalid,
        # an error message is added to
        # the `errors` attribute of the `LoginForm` object.

        # Args:
        #     self (LoginForm): The `LoginForm` object to validate.

        # Returns:
        #     A boolean indicating whether the `login_user` and `login_password`
        #     attributes are valid and
        #     there are no errors. Returns `True` if the attributes are valid
        #     and there are no errors,
        #     otherwise `False`.
        # """
        if not self.login_user or not (self.login_user.__contains__("@")):
            self.errors.append("Email is required")
        if not self.login_password or not len(self.login_password) >= 4:
            self.errors.append("A valid password is required")
        if not self.errors:
            return True
        return False

LOGIN_TEMPLATE = "loginpage.html"

# --------------------------------------------------------------------------
# Home Page
# --------------------------------------------------------------------------
@APP.get("/", response_class=HTMLResponse)
def home_page(request: Request):
    """Home Page"""
    try:
        user = get_current_user_from_cookie(request)
    except ValueError:
        user = None
    context = {
        "user": user,
        "request": request,
    }
    return TEMPLATES.TemplateResponse("homepage.html", context)

# --------------------------------------------------------------------------
# Login - GET
# --------------------------------------------------------------------------

@APP.get("/auth/login", response_class=HTMLResponse)
def login_get(request: Request):
    
    context = {
        "request": request
    }
    return TEMPLATES.TemplateResponse(LOGIN_TEMPLATE, context)

# --------------------------------------------------------------------------
# Login - POST
# --------------------------------------------------------------------------

@APP.post("/auth/login", response_class=HTMLResponse)
async def login_post(request: Request):
#     This is a Python code block that likely handles form submission for a login form in a web application.

# The code creates a new LoginForm instance with the current request object and calls the load_data() method to load form data from the request. It then checks if the form is valid by calling the is_valid() method on the form. If the form is not valid, it raises an HTTPException with a 400 status code and "Form data is not valid" detail message.

# If the form data is valid, the code generates a new access token by calling the login_for_access_token() function and passing in the response object and the form_data object. The login_for_access_token() function likely handles the actual authentication and generates a new access token, which is then stored in a cookie or header on the response object.

# If an HTTPException is raised during form validation, the code catches the exception, updates the LoginForm instance with an empty message and the exception detail, and returns a TemplateResponse object with the login template and the form data dictionary.

# If any other exception is raised, the code catches the exception, raises an HTTPException with a 500 status code and the exception message as the detail, and logs the exception using a logger object
    form = LoginForm(request)
    await form.load_data()
    try:
        if not await form.is_valid():
            # Form data is not valid
            raise HTTPException(status_code=400, detail="Form data is not valid")
        # Form data is valid, generate new access token
        response = RedirectResponse("/", status.HTTP_302_FOUND)
        login_for_access_token(response=response, form_data=form)
        form.__dict__.update(msg="Login Successful!")
        return response
    except HTTPException as exception:
        # Catch HTTPException and update form with error message
        form.__dict__.update(msg="")
        form.__dict__.get("errors").append(exception.detail)
        return TEMPLATES.TemplateResponse(LOGIN_TEMPLATE, form.__dict__)
    except Exception as exception:
        # Catch any other exception and return 500 Internal Server Error
        raise HTTPException(status_code=500, detail=str(exception)) from exception


# --------------------------------------------------------------------------
# signup - GET
# --------------------------------------------------------------------------
@APP.get("/signup", response_class=HTMLResponse)
def get_signup_page(request: Request):
#     This is a Python code block that likely renders a signup page for a web application.

# The code uses the TEMPLATES object, which is an instance of the Jinja2Templates class 
# from 
# the fastapi.templating module in FastAPI, to render the "signuppage.html" template. The template is passed a dictionary that includes the request object.

# If an exception occurs during template rendering, the code logs the error using a logger object and raises an HTTPException with a 500 status code and a "Server error" detail message. The logger.exception() method logs the exception and its traceback to the logger object.
    
    try:
        return TEMPLATES.TemplateResponse("signuppage.html", {"request": request})
    except Exception as exception:
        # Log the error and raise an HTTPException with a 500 status code
        # to indicate a server error to the client.
        logger.exception(f"An error occurred while rendering the signup page: {exception}")
        raise HTTPException(status_code=500, detail="Server error") from exception

# --------------------------------------------------------------------------
# signup - POST
# --------------------------------------------------------------------------
@APP.post("/signup", response_class=HTMLResponse)
def signup_page(request: Request, username: str = Form(...), email: str = Form(...),\
        password: str = Form(...), cpassword: str = Form(...)):
    hashed_password = hash_password(password)
    user = User(Username=username, Email=email, Password=hashed_password,\
    CPassword=cpassword)
    data = SIGNUP_COLLECTION.find_one({"Email":email})
#     The code first checks if the data variable is empty and whether the password matches the cpassword (confirm password) field. If both conditions are true, a new user document is inserted into the MongoDB collection named SIGNUP_COLLECTION using the insert_one() method with the user data from a dictionary created from the user model's dict() method.

# If the email address already exists in the collection, the code generates a random string and appends it to the username in the email address to create a new, unique email address. It then returns a response with the signuppage.html template and an error message indicating that the email already exists.

# If the data variable is missing a required parameter, a KeyError exception is raised with an error message indicating the missing parameter. If any other exception is raised, a generic "Internal Server Error" message is returned with a 500 HTTP status code.

# Without more context, it's difficult to provide more specific comments on this code block.

    try:
        if not data and (password == cpassword):
            SIGNUP_COLLECTION.insert_one(user.dict())
            return TEMPLATES.TemplateResponse(LOGIN_TEMPLATE, {"request":request})
        random_string = ''.join(random.choice(string.ascii_letters) for i in range(5))
        email = f"{email.split('@')[0]}_{random_string}@{email.split('@')[1]}"
        return TEMPLATES.TemplateResponse("signuppage.html", \
            {"request":request, "message":"Email already exists", "SUGGESTED_EMAIL":email})
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing parameter: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Internal Server Error") from exc
# --------------------------------------------------------------------------
# Logout
# --------------------------------------------------------------------------
@APP.get("/auth/logout", response_class=HTMLResponse)
def logout_get():
#     This is a Python code block that likely logs out a user from a web application by deleting their authentication cookie.

# The code creates a new RedirectResponse instance with the URL "/auth/login". It then calls the delete_cookie() method on the response object, passing in the name of the cookie to delete, which is stored in the COOKIE_NAME variable from the SETTING object.

# The code then returns the response object, which should cause the user's browser to redirect to the login page and delete the authentication cookie.

# If the COOKIE_NAME variable is not found, a KeyError exception is raised with an error message indicating that the cookie name was not found. If any other exception is raised, a generic "Internal Server Error" message is returned with a 500 HTTP status code.

# Without more context, it's difficult to provide more specific comments on this code block.
 
    try:
        response = RedirectResponse(url="/auth/login")
        response.delete_cookie(SETTING.COOKIE_NAME)
        return response
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="Cookie name not found.") from exc
    except Exception as exception:
        raise HTTPException(status_code=500, detail=str(exception)) from exception
