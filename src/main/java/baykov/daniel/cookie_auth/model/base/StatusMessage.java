package baykov.daniel.cookie_auth.model.base;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@Builder
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StatusMessage {

	public static final String SUCCESS_CODE = "SUCCESS";
	public static final String ERROR_CODE = "ERROR";
	public static final int STATUS_SUCCESS = 0;
	public static final int STATUS_ERROR = 1;
	public static final int STATUS_OVERRIDE = 2;

	protected String externalRef;
	protected String message;
	protected String messageCode;
	protected String refNo;
	protected int status;
	protected String statusDesc;
	protected int httpStatusCode;

	@JsonInclude(JsonInclude.Include.NON_EMPTY)
	protected List<StatusFieldError> fieldErrors;

	@JsonInclude(JsonInclude.Include.NON_EMPTY)
	protected List<StatusObjectError> globalErrors;

	public StatusMessage() {
		super();
		this.status = STATUS_SUCCESS;
		this.httpStatusCode = HttpStatus.OK.value();
		this.fieldErrors = new ArrayList<>();
		this.globalErrors = new ArrayList<>();
	}
	
	public StatusMessage(int status, String messageCode, int httpStatusCode) {
		this();
		this.status = status;
		this.httpStatusCode = httpStatusCode;
		this.messageCode = messageCode;
	}

	public StatusMessage(int status, String messageCode) {
		this(status, messageCode, status == 0 ? HttpStatus.OK.value() : HttpStatus.BAD_REQUEST.value());
	}

	public StatusMessage(int status, String statusDesc, String messageCode, String message, String refNo, String externalRef) {
		this(status, messageCode);
		this.statusDesc = statusDesc;
		this.message = message;
		this.refNo = refNo;
		this.externalRef = externalRef;
	}

	public StatusMessage(int status, String statusDesc, String messageCode, int httpStatusCode, String message) {
		this(status, statusDesc, messageCode, message, "", "");
		this.httpStatusCode = httpStatusCode;
	}
	
	public boolean isSuccess() {
		return this.status == STATUS_SUCCESS;
	}

	public static StatusMessage success() {
		return StatusMessage.builder()
				.status(STATUS_SUCCESS)
				.messageCode(SUCCESS_CODE)
				.httpStatusCode(HttpStatus.OK.value())
				.build();
	}

	public static StatusMessageBuilder error() {
		return StatusMessage.builder()
				.status(STATUS_ERROR)
				.messageCode(ERROR_CODE)
				.httpStatusCode(HttpStatus.BAD_REQUEST.value());
	}

	public static StatusMessageBuilder error(String messageCode, String message) {
		return StatusMessage.builder()
				.status(STATUS_ERROR)
				.messageCode(messageCode)
				.message(message)
				.httpStatusCode(HttpStatus.BAD_REQUEST.value());
	}

	public static StatusMessageBuilder error(int httpStatusCode, String messageCode, String message) {
		return StatusMessage.builder()
				.status(STATUS_ERROR)
				.messageCode(messageCode)
				.message(message)
				.httpStatusCode(httpStatusCode);
	}

	public void addFieldError(StatusFieldError fieldError) {
		this.fieldErrors.add(fieldError);
	}

	public void addGlobalError(StatusObjectError globalError) {
		this.globalErrors.add(globalError);
	}
}
