package utils

import (
	"errors"
	"reflect"
	"strings"
	"time"
)

// ValidateRequired accepts an instance of any type and checks whether or not all fields are filled
func ValidateRequired(instance interface{}) error {

	v := reflect.ValueOf(instance)

	for i := 0; i < v.NumField(); i++ {

		// Check if the field's exported otherwise .Interface() will panic
		if v.Type().Field(i).PkgPath != "" {
			continue
		}

		// check if the field has the required tag
		if v.Type().Field(i).Tag.Get("required") != "true" {
			continue
		}
		fieldValue := v.Field(i).Interface()
		zeroFieldValue := reflect.Zero(reflect.TypeOf(v.Field(i).Interface())).Interface()
		if reflect.DeepEqual(fieldValue, zeroFieldValue) {
			return GenericEmptyRequiredField(v.Type().Field(i).Tag.Get("json"))
		}
	}
	return nil
}

// GetFieldValueByName retrieves the value of a specified field from the provided instance
func GetFieldValueByName(instance interface{}, fieldName string) (interface{}, error) {

	// Check if the field's name is capitalized to make sure its exported otherwise .Interface() will panic
	if !IsCapitalized(fieldName) {
		return nil, errors.New("you are trying to access an unexported field")
	}

	v := reflect.ValueOf(instance).FieldByName(fieldName)

	// check if the field exists
	zeroReflectValue := reflect.Zero(reflect.TypeOf(reflect.Value{})).Interface()
	if reflect.DeepEqual(v, zeroReflectValue) {
		return nil, errors.New("Field: " + fieldName + " has not been declared.")
	}

	// check if the field contains a value
	fieldValue := v.Interface()
	zeroFieldValue := reflect.Zero(reflect.TypeOf(v.Interface())).Interface()

	if reflect.DeepEqual(fieldValue, zeroFieldValue) {
		return nil, GenericEmptyRequiredField(fieldName)
	}

	// if everything is ok, return the value of the field
	return v.Interface(), nil
}

// StructToMap converts a non nil struct to a map of map[string]interface{}
func StructToMap(instance interface{}) map[string]interface{} {

	if instance == nil {
		return nil
	}

	var fl reflect.StructField
	contents := make(map[string]interface{})

	v := reflect.ValueOf(instance)
	for i := 0; i < v.NumField(); i++ {
		fl = v.Type().Field(i)
		// Check if the field's exported otherwise .Interface() will panic
		if fl.PkgPath != "" {
			continue
		}
		contents[fl.Name] = v.Field(i).Interface()
	}

	return contents
}

// IsCapitalized returns whether or not not a string is capitalized
func IsCapitalized(str string) bool {

	if str == "" {
		return false
	}

	return string([]rune(str)[0]) == strings.ToUpper(string([]rune(str)[0])) // check for a capitalized name (in utf-8)
}

// CopyFields finds same named field between two structs and copies the values from one to an other
func CopyFields(from interface{}, to interface{}) error {

	iv := reflect.Value{} // zero reflect value
	fromV := reflect.ValueOf(from)
	toV := reflect.ValueOf(to)
	fl := reflect.StructField{}

	// it requires a pointer to a struct so its fields are addressable in order to be set through the Set() method
	if toV.Kind() != reflect.Ptr {
		return errors.New("CopyFields needs a pointer to a struct as a second argument")
	}

	for i := 0; i < fromV.NumField(); i++ {
		fl = fromV.Type().Field(i)
		if fl.PkgPath != "" {
			continue
		}
		if toV.Elem().FieldByName(fl.Name) != iv { // if the field with that name doesn't exist in the struct it will return a zero reflect value
			toV.Elem().FieldByName(fl.Name).Set(fromV.FieldByName(fl.Name))
		}
	}
	return nil
}

// ZuluTimeNow returns the current UTC time in zulu format
func ZuluTimeNow() string {
	return time.Now().UTC().Format(ZULU_FORM)
}
