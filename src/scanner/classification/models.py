from enum import Enum


class EndpointClass(str, Enum):
    ADMIN_PORTAL = "Admin Portal"
    ADMIN = "Admin"
    PAYMENT_GATEWAY = "Payment Gateway"
    CHECKOUT = "Checkout"
    PAYMENT = "Payment"
    AUTHENTICATION = "Authentication"
    IDENTITY = "Identity"
    CUSTOMER_DATA = "Customer Data"
    API = "API"
    UPLOAD = "Upload"
    STATIC = "Static"
    STATIC_ASSETS = "Static Assets"
    MAIN_APP = "Main Application"
    FEED = "Feed"
    MEDIA = "Media"
    DOWNLOAD = "Download"
    THIRD_PARTY = "Third-party"


class AssetCategory(str, Enum):
    FIRST_PARTY = "First-party"
    BUSINESS_ASSET = "Business Asset"
    ADMIN_PORTAL = "Admin Portal"
    PAYMENT_GATEWAY = "Payment Gateway"
    AUTHENTICATION = "Authentication"
    IDENTITY = "Identity"
    CUSTOMER_DATA = "Customer Data"
    THIRD_PARTY = "Third-party"
    CDN = "CDN"
    ANALYTICS = "Analytics"
    OAUTH = "OAuth"
    PAYMENT = "Payment"
    EMBEDDED_WIDGETS = "Embedded Widgets"
