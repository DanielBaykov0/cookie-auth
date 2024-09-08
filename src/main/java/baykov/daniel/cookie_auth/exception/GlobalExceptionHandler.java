package baykov.daniel.cookie_auth.exception;

import baykov.daniel.cookie_auth.model.base.StatusFieldError;
import baykov.daniel.cookie_auth.model.base.StatusMessage;
import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.model.base.StatusObjectError;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.UncategorizedSQLException;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.WebUtils;

import java.sql.SQLException;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final int CUSTOM_ERROR_CODE = 20000;
    private static final String CUSTOM_ERROR_CODE_STRING = "CUSTOM_ERROR_CODE";

    private StatusMessage createStatusMessageFromBindingResult(BindingResult bindingResult) {
        StatusMessage errorBody = new StatusMessage(1, "VALIDATION_ERROR");

        for (FieldError fieldError : bindingResult.getFieldErrors()) {
            StatusFieldError statusFieldError = new StatusFieldError(fieldError);
            errorBody.addFieldError(statusFieldError);
        }

        for (ObjectError globalError : bindingResult.getGlobalErrors()) {
            errorBody.addGlobalError(new StatusObjectError(globalError));
        }

        return errorBody;
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
    protected ResponseEntity<Object> handleValidationExceptions(Exception ex, WebRequest request) {
        BindingResult bindingResult = ex instanceof MethodArgumentNotValidException methodArgumentNotValidException
                ? methodArgumentNotValidException.getBindingResult()
                : ((BindException) ex).getBindingResult();
        StatusMessage errorBody = createStatusMessageFromBindingResult(bindingResult);
        return handleExceptionInternal(ex, errorBody, new HttpHeaders(), HttpStatus.OK, request);
    }

    @ExceptionHandler(StatusMessageException.class)
    public ResponseEntity<Object> handleGlobalException(StatusMessageException ex, WebRequest request) {
        return handleExceptionInternal(ex, ex.getStatusMessage(), new HttpHeaders(), HttpStatus.OK, request);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Object> handleGlobalException(ResponseStatusException ex, WebRequest request) {
        return handleExceptionInternal(ex, null, new HttpHeaders(), (HttpStatus) ex.getStatusCode(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGlobalException(Exception ex, WebRequest request) {
        return handleExceptionInternal(ex, null, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    /**
     * A single place to customize the response body of all exception types.
     * <p>
     * The default implementation sets the
     * {@link WebUtils#ERROR_EXCEPTION_ATTRIBUTE} request attribute and creates a
     * {@link ResponseEntity} from the given body, headers, and status.
     *
     * @param ex      the exception
     * @param body    the body for the response
     * @param headers the headers for the response
     * @param status  the response status
     * @param request the current request
     */
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex,
            @Nullable Object body,
            HttpHeaders headers,
            HttpStatus status,
            WebRequest request) {
        boolean logError = true;
        if (ex instanceof StatusMessageException statusMessageException) {
            if (statusMessageException.getStatusMessage().getStatus() == 0) {
                logError = false;
            }
        }

        if (logError) {
            log.error(ex.getMessage(), ex);
        }

        if (ex instanceof UncategorizedSQLException && ex.getCause() instanceof SQLException) {
            SQLException cause = (SQLException) ex.getCause();
            int errorCode = cause.getErrorCode();

            if (errorCode == CUSTOM_ERROR_CODE) {
                String messageCode = CUSTOM_ERROR_CODE_STRING;
                String message = cause.getMessage();
                String[] messageParts = cause.getMessage().split("~");

                if (messageParts.length > 2) {
                    messageCode = messageParts[1];
                    message = messageParts[2];
                }

                body = new StatusMessage(1, "ERROR", messageCode, 400, message);
                status = HttpStatus.OK;
            }
        }

        if (body == null) {
            body = new StatusMessage(1, status.name());
        }

        if (HttpStatus.INTERNAL_SERVER_ERROR.equals(status)) {
            request.setAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, ex, RequestAttributes.SCOPE_REQUEST);
        }

        return ResponseEntity
                .status(status)
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }
}
