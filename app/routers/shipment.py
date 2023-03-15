# pylint: disable=import-error
# """The above code is importing the necessary libraries for the program to run.

from dotenv import load_dotenv
from pymongo.errors import PyMongoError
from fastapi.responses import HTMLResponse
from fastapi import Form, Request, HTTPException, Depends, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from config import SETTING
from models import Shipment
from models import User
from routers.user import get_current_user_from_token, get_current_user_from_cookie


load_dotenv()

APP = APIRouter(tags=["creating shipment api's"])

APP.mount("/static", StaticFiles(directory="static"), name="static")

TEMPLATES = Jinja2Templates(directory="templates")

CLIENT = SETTING.CLIENT

SHIPMENT_COLLECTION = SETTING.SHIPMENT_COLLECTION

SHIPMENT_TEMPLATE = "shipmentpage.html"

# --------------------------------------------------------------------------
# Create shipment Page GET
# --------------------------------------------------------------------------
# Create shipment page that only logged in users can access.


@APP.get("/shipment", response_class=HTMLResponse)
def get_shipment_page(request: Request, user: User = Depends(get_current_user_from_token)):
   
    try:
        context = {
            "user": user,
            "request": request
        }
        return TEMPLATES.TemplateResponse(SHIPMENT_TEMPLATE, context)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --------------------------------------------------------------------------
# Create shipment Page POST
# --------------------------------------------------------------------------
# Create shipment page that only logged in users can access.


@APP.post("/shipment", response_class=HTMLResponse)
def post_shipment_page(request: Request, shipment_invoice_number:
                       str = Form(...), container_number: int = Form(...), description: str = Form(...),
                       route_details: str = Form(...), goods_type: str = Form(...), device: str = Form(...),
                       delivery_date: str = Form(...), po_number: int = Form(...), delivery_number: int = Form(...),
                       ndcnumber: int = Form(...), batch_id: int = Form(...), serialnumberofgoods: int = Form(...)):
    """this is shipment post method"""
    user_name = get_current_user_from_cookie(request)
    user = Shipment(Shipment_Invoice_Number=shipment_invoice_number, \
        Container_Number=container_number, Description=description, \
            Route_Details=route_details, Goods_Type=goods_type, \
                Device=device, Expected_Delivery_Date=delivery_date,\
                     Po_Number=po_number, Delivery_number=delivery_number,\
                         NDCNumber=ndcnumber, Batch_Id=batch_id, \
                            Serialnumberofgoods=serialnumberofgoods,\
                                 mailid=user_name["Email"])
    data = SHIPMENT_COLLECTION.find_one(
        {"Shipment_Invoice_Number": shipment_invoice_number})
    try:
        if not data:
            SHIPMENT_COLLECTION.insert_one(user.dict())
            return TEMPLATES.TemplateResponse(SHIPMENT_TEMPLATE,
                                              {"request": request, "user": user_name,
                                               "success_message": "Success! Your shipment has been created"})
        return TEMPLATES.TemplateResponse(SHIPMENT_TEMPLATE,
                                          {"request": request, "user": user_name,
                                           "message": "*Shipment_Invoice_Number already exists"})
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail="Invalid input. Please check your input values.") from exc
    except PyMongoError as exc:
        raise HTTPException(
            status_code=500, detail="Database error. Please try again later.") from exc
    except Exception as exception:
        raise HTTPException(
            status_code=500, detail=f"Internal Server Error: {str(exception)}") from exception

# --------------------------------------------------------------------------
# show shipment -GET
# --------------------------------------------------------------------------


@APP.get("/show-shipment", response_class=HTMLResponse)
def get_created_shipments(request: Request, user: User = Depends(get_current_user_from_token)):
    # """
    # Retrieves a list of shipments created by the currently logged-in user.
    # Args:
    # request (Request): The incoming HTTP request.
    # Returns:
    # A TemplateResponse containing the list of shipments and the user's information.
    # """
    try:
        shipment_user = get_current_user_from_cookie(request)
        shipment_data = list(SHIPMENT_COLLECTION.find(
            {"mailid": shipment_user["Email"]}, {'_id': 0}))
        if shipment_data:
            for i in shipment_data:
                value = i["Route_Details"]
            string = value
            words = string.split()
            delivery_from = words[0]
            delivery_to = words[-1]
            context = {
                "shipment_user": shipment_user,
                "shipment_data": shipment_data,
                "request": request,
                "user": user,
                "delivery_from": delivery_from,
                "delivery_to": delivery_to,
                "src": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd\
                    9GcTIUTypras1jl3DXjTzGYKLgldCMvSub21cvNV_WLSF8A&s"
            }
            return TEMPLATES.TemplateResponse("createdshipments.html", context)
        context = {
            "shipment_user": shipment_user,
            "request": request,
            "shipment": " no shipments have been created"
        }
        return TEMPLATES.TemplateResponse("noshipmentsfound.html", context)
    except Exception as exception:
        raise HTTPException(
            status_code=500, detail=str(exception)) from exception
