package baykov.daniel.cookie_auth.model.base;

import lombok.Getter;

@Getter
public class StatusMessageException extends RuntimeException{
	
	private final StatusMessage statusMessage;

	public StatusMessageException(StatusMessage statusMessage) {
		super(statusMessage.getMessage());
		this.statusMessage = statusMessage;
	}

	public static StatusMessageException error(String messageCode, String message) {
		StatusMessage statusMessage = StatusMessage.error(messageCode, message).build();
		return new StatusMessageException(statusMessage);
	}

	public static StatusMessageException error(int httpStatusCode, String messageCode, String message) {
		StatusMessage statusMessage = StatusMessage.error(httpStatusCode, messageCode, message).build();
		return new StatusMessageException(statusMessage);
	}
}
