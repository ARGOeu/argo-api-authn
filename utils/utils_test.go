package utils

import (
	"testing"

	"errors"

	"github.com/stretchr/testify/suite"
)

type UtilsTestSuite struct {
	suite.Suite
	TestStructList map[string]interface{}
}

type TestStruct struct {
	Field1 string   `json:"field_1"required:"true"`
	Field2 int      `json:"field_2"required:"true"`
	Field3 []string `json:"field_3"required:"true"`
	Field4 float64  `json:"field_4"required:"true"`
	Field5 *string  `json:"field_5"required:"true"`
	field6 string   // will be skipped
	Field7 string   // will not cause an error even if it isn't filled
}

func (suite *UtilsTestSuite) SetUpUtilsTestSuite() {

	// initialize the map
	suite.TestStructList = make(map[string]interface{})

	tStr := "tStr"

	ts1 := TestStruct{"44", 44, []string{"t1", "t2"}, 12.33, &tStr, "unexported", ""}
	ts2 := TestStruct{"", 44, []string{"t1", "t2"}, 12.33, &tStr, "unexported", ""}

	// fill the map
	suite.TestStructList["ts1"] = ts1
	suite.TestStructList["ts2"] = ts2
	suite.TestStructList["ts1_ptr"] = &ts1
	suite.TestStructList["ts2_ptr"] = &ts2

}

func (suite *UtilsTestSuite) TestCheckForNulls() {

	// tests the normal case
	suite.Nil(ValidateRequired(suite.TestStructList["ts1"]))

	// tests the case of an object containing a field which is empty
	suite.Equal(errors.New("empty value for field: field_1"), ValidateRequired(suite.TestStructList["ts2"]))
}

func (suite *UtilsTestSuite) TestGetFieldByName() {

	// tests the normal case - without a ptr value
	val1, err1 := GetFieldValueByName(suite.TestStructList["ts1"], "Field1")

	// tests the case of a missing field
	val2, err2 := GetFieldValueByName(suite.TestStructList["ts1"], "Field10")

	// tests the case of an empty field
	val3, err3 := GetFieldValueByName(suite.TestStructList["ts2"], "Field1")

	// tests the case of an unexported field
	val4, err4 := GetFieldValueByName(suite.TestStructList["ts2"], "field6")

	// tests the normal case - with a ptr value
	val5, err5 := GetFieldValueByName(suite.TestStructList["ts1_ptr"], "Field1")

	// tests the case of a missing field
	val6, err6 := GetFieldValueByName(suite.TestStructList["ts1_ptr"], "Field10")

	// tests the case of an empty field
	val7, err7 := GetFieldValueByName(suite.TestStructList["ts2_ptr"], "Field1")

	// tests the case of an unexported field
	val8, err8 := GetFieldValueByName(suite.TestStructList["ts2_ptr"], "field6")

	suite.Equal("44", val1.(string))
	suite.Nil(val2)
	suite.Nil(val3)
	suite.Nil(val4)
	suite.Equal("44", val5.(string))
	suite.Nil(val6)
	suite.Nil(val7)
	suite.Nil(val8)

	suite.Nil(err1)
	suite.Equal("Field: Field10 has not been declared.", err2.Error())
	suite.Equal("empty value for field: Field1", err3.Error())
	suite.Equal("you are trying to access an unexported field", err4.Error())
	suite.Nil(err5)
	suite.Equal("Field: Field10 has not been declared.", err6.Error())
	suite.Equal("empty value for field: Field1", err7.Error())
	suite.Equal("you are trying to access an unexported field", err8.Error())

}

func (suite *UtilsTestSuite) TestStructToMap() {

	//tests the normal case with unexported field
	tStr := "tStr"
	expMap := map[string]interface{}{"Field1": "44", "Field2": 44, "Field3": []string{"t1", "t2"}, "Field4": 12.33, "Field5": &tStr, "Field7": ""}
	suite.Equal(expMap, StructToMap(suite.TestStructList["ts1"]))

	//tests the case of nil input
	suite.Nil(StructToMap(nil))

}

func (suite *UtilsTestSuite) TestIsCapitalized() {

	suite.Equal(true, IsCapitalized("Str1"))
	suite.Equal(false, IsCapitalized("str1"))
	suite.Equal(false, IsCapitalized(""))
}

func (suite *UtilsTestSuite) TestCopyFields() {

	// normal case with unexported field
	ts1 := TestStruct{}
	tStr := "tStr"
	expTs1 := TestStruct{"44", 44, []string{"t1", "t2"}, 12.33, &tStr, "", ""}
	err1 := CopyFields(suite.TestStructList["ts1"], &ts1)

	// error case with non pointer struct argument
	ts2 := TestStruct{}
	expTs2 := TestStruct{}

	err2 := CopyFields(suite.TestStructList["ts1"], ts2)

	suite.Equal(expTs1, ts1)
	suite.Equal(expTs2, ts2)

	suite.Equal("CopyFields needs a pointer to a struct as a second argument", err2.Error())
	suite.Nil(err1)

}

func TestUtilsTestSuite(t *testing.T) {
	utilsTestSuite := new(UtilsTestSuite)
	utilsTestSuite.SetUpUtilsTestSuite()
	suite.Run(t, utilsTestSuite)

}
