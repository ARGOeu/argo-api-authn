package utils

import (
	"errors"
	"fmt"
)

// API Related Errors

var APIErrBadRequest = func(msg string) *APIError {
	msg = fmt.Sprintf("Poorly formatted JSON. %v", msg)
	return &APIError{msg, 400, "BAD REQUEST"}
}

var APIErrUnauthorized = func(msg string) *APIError {
	return &APIError{msg, 401, "UNAUTHORIZED"}
}

var APIErrNotFound = func(resource string) *APIError {
	msg := fmt.Sprintf("%v was not found", resource)
	return &APIError{msg, 404, "NOT FOUND"}
}

var APIErrConflict = func(resource string, field string, value string) *APIError {
	msg := fmt.Sprintf("%v object with %v: %v already exists", resource, field, value)
	return &APIError{msg, 409, "CONFLICT"}
}

var APIErrEmptyRequiredField = func(resource string, msg string) *APIError {
	return &APIError{fmt.Sprintf("%v object contains empty fields. %v", resource, msg), 422, "UNPROCESSABLE ENTITY"}
}

var APIErrInvalidFieldContent = func(field string, reason string) *APIError {
	msg := fmt.Sprintf("Field: %v contains invalid data. %v", field, reason)
	return &APIError{msg, 422, "UNPROCESSABLE ENTITY"}
}

var APIErrUnsupportedContentNonVerbose = func(place, content string) *APIError {
	msg := fmt.Sprintf("%v: %v is not yet supported", place, content)
	return &APIError{msg, 422, "UNPROCESSABLE ENTITY"}
}

var APIErrUnsupportedContent = func(place, content string, supported string) *APIError {
	msg := fmt.Sprintf("%v: %v is not yet supported.%v", place, content, supported)
	return &APIError{msg, 422, "UNPROCESSABLE ENTITY"}
}

var APIErrDatabase = func(msg string) *APIError {
	msg = fmt.Sprintf("Database Error: %v", msg)
	return &APIError{msg, 500, "INTERNAL SERVER ERROR"}
}

var APIGenericInternalError = func(msg string) error {
	return &APIError{"Internal Error: " + msg, 500, "INTERNAL SERVER ERROR"}
}

// Generic Errors

var GenericEmptyRequiredField = func(fieldName string) error {
	return errors.New(fmt.Sprintf("empty value for field: %v", fieldName))
}

// StructGenericEmptyRequiredField also contains struct information
var StructGenericEmptyRequiredField = func(strct string, reason string) error {
	return errors.New(fmt.Sprintf("%v object contains empty fields. %v", strct, reason))
}
