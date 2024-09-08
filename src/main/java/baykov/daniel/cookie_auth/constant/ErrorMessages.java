package baykov.daniel.cookie_auth.constant;

import lombok.experimental.UtilityClass;

@UtilityClass
public final class ErrorMessages {

    public static final String INCORRECT_CREDENTIALS = "Incorrect email or password. Please try again.";

    public static final String REFRESH_TOKEN_EXPIRED = "Refresh Token has expired!";
    public static final String PREVIOUS_TOKEN_NOT_EXPIRED = "Previous Token has not expired yet!";
    public static final String PREVIOUS_TOKEN_EXPIRED = "Previous Token has expired!";

    public static final String NOT_AUTHENTICATED = "User not authenticated!";
    public static final String USER_NOT_FOUND_BY_EMAIL = "User not found with email: ";
    public static final String EMAIL_NOT_VERIFIED = "User email not verified!";

    public static final String EMAIL_ALREADY_EXISTS = "Email already exists!";
    public static final String TOKEN_NOT_FOUND = "Token not found!";
    public static final String EMAIL_ALREADY_CONFIRMED = "Email already confirmed!";

    public static final String TOKEN_EXPIRED = "Token expired!";
    public static final String INVALID_TOKEN_TYPE = "Invalid Token Type!";

    public static final String EMAIL_SEND_FAILURE = "Failed to send email!";
    public static final String EMAIL_NOT_CONFIRMED = "Email has not been confirmed!";
    public static final String USER_NOT_VERIFIED_REVIEW = "Please verify your email before posting a review!";
    public static final String USER_NO_REVIEW = "User has not yet posted a review!";

    public static final String AVAILABLE_BOOKS_BIGGER_THAN_TOTAL = "Total Number of Books should be equal or greater than number of Available Books!";
    public static final String QUANTITY_EXCEEDS_PRODUCTS_AVAILABLE = "Requested quantity exceeds available copies!";
    public static final String NEGATIVE_QUANTITY = "Please enter a valid quantity!";
    public static final String QUANTITY_EXCEEDS_ADDED_PRODUCTS = "Requested quantity exceeds added copies!";
    public static final String CANT_BUY_MORE_THAN_ONE = "Item is already in your Shopping Cart. You can buy only one copy!";
    public static final String CAN_BUY_ONLY_ONE = "You can buy only one copy!";
    public static final String EBOOK_BOUGHT_ALREADY = "You have already purchased this ebook!";
    public static final String AUDIOBOOK_BOUGHT_ALREADY = "You have already purchased this audiobook!";
    public static final String UNKNOWN_PRODUCT_TYPE = "Unknown product type!";

    public static final String INVALID_JWT_TOKEN = "Invalid JWT Token";
    public static final String EXPIRED_JWT_TOKEN = "Expired JWT Token";
    public static final String UNSUPPORTED_JWT_TOKEN = "Unsupported JWT Token";
    public static final String JWT_CLAIM_EMPTY = "JWT claim string is empty";
    public static final String JWT_ERR = "JWT-ERR";
    public static final String TOKEN_MISSING_ERR = "T-M-ERR";
    public static final String PREVIOUS_TOKEN_NOT_EXPIRED_ERR = "PT-NE-ERR";
    public static final String EMAIL_EXISTS_ERR = "E-E-ERR";
    public static final String RESOURCE_NOT_FOUND_ERR = "R-NF-ERR";
    public static final String INVALID_TOKEN_TYPE_ERR = "I-TT-ERR";
    public static final String TOKEN_EXPIRED_ERR = "T-E-ERR";
    public static final String EMAIL_ALREADY_CONFIRMED_ERR = "E-AC-ERR";
    public static final String EMAIL_ALREADY_VERIFIED_ERR = "E-AV-ERR";
    public static final String USER_NOT_FOUND_BY_EMAIL_ERR = "U-NFE-ERR";
    public static final String EMAIL_NOT_VERIFIED_ERR = "E-NV-ERR";
    public static final String UNAUTHORIZED_ERR = "U-ERR";
    public static final String UNAUTHORIZED = "Unauthorized.";
}
