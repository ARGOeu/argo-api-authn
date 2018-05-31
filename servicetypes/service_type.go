package servicetypes

import (
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	uuid2 "github.com/satori/go.uuid"
)

type ServiceType struct {
	Name           string   `json:"name" required:"true"`
	Hosts          []string `json:"hosts" required:"true"`
	AuthTypes      []string `json:"auth_types" required:"true"`
	AuthMethod     string   `json:"auth_method" required:"true"`
	UUID           string   `json:"uuid"`
	RetrievalField string   `json:"retrieval_field" required:"true"`
	CreatedOn      string   `json:"created_on"`
}

type ServiceList struct {
	ServiceTypes []ServiceType `json:"service_types"`
}

// CreateServiceType creates a new service type after validating the service
func CreateServiceType(service ServiceType, store stores.Store, cfg config.Config) (ServiceType, error) {

	var qServices []stores.QServiceType
	var qService stores.QServiceType
	var err error

	// check if the authentication methods are supported
	if err = service.hasValidAuthMethod(cfg); err != nil {
		return ServiceType{}, err
	}

	// check if the authentication type is supported
	if err = service.hasValidAuthTypes(cfg); err != nil {
		return ServiceType{}, err
	}

	// check that the name of the service type is unique
	if qServices, err = store.QueryServiceTypes(service.Name); err != nil {
		return ServiceType{}, err
	}

	if len(qServices) > 0 {
		err = utils.APIErrConflict(service, "name", service.Name)
		return ServiceType{}, err
	}

	// generate UUID
	uuid := uuid2.NewV4().String()

	// insert the service type
	if qService, err = store.InsertServiceType(service.Name, service.Hosts, service.AuthTypes, service.AuthMethod, uuid, service.RetrievalField, utils.ZuluTimeNow()); err != nil {
		return ServiceType{}, err
	}

	// convert the qService to a ServiceType
	if err = utils.CopyFields(qService, &service); err != nil {
		err = utils.APIErrDatabase(err.Error())
		return ServiceType{}, err
	}

	return service, err
}

// FindServiceTypeByName queries the datastore to find a service type associated with the provided argument name
func FindServiceTypeByName(name string, store stores.Store) (ServiceType, error) {

	var qServices []stores.QServiceType
	var service ServiceType
	var err error

	if qServices, err = store.QueryServiceTypes(name); err != nil {
		return ServiceType{}, err
	}

	if len(qServices) == 0 {
		err = utils.APIErrNotFound("ServiceType")
		return ServiceType{}, err
	}

	if len(qServices) > 1 {
		err = utils.APIErrDatabase("Multiple service-types with the same name: " + name)
		return ServiceType{}, err
	}

	if err := utils.CopyFields(qServices[0], &service); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	return service, err
}

// FindServiceTypeByUUID queries the datastore to find a service type associated with the provided argument uuid
func FindServiceTypeByUUID(uuid string, store stores.Store) (ServiceType, error) {

	var qServices []stores.QServiceType
	var service ServiceType
	var err error

	if qServices, err = store.QueryServiceTypesByUUID(uuid); err != nil {
		return ServiceType{}, err
	}

	if len(qServices) == 0 {
		err = utils.APIErrNotFound("ServiceType")
		return ServiceType{}, err
	}

	if len(qServices) > 1 {
		err = utils.APIErrDatabase("Multiple service-types with the same uuid: " + uuid)
		return ServiceType{}, err
	}

	if err := utils.CopyFields(qServices[0], &service); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	return service, err
}

// FindAllServiceTypes returns all the service types from the datastore
func FindAllServiceTypes(store stores.Store) (ServiceList, error) {

	var qServices []stores.QServiceType
	var services = []ServiceType{}
	var err error

	if qServices, err = store.QueryServiceTypes(""); err != nil {
		return ServiceList{ServiceTypes: services}, err
	}

	for _, qs := range qServices {
		_service := &ServiceType{}
		if err := utils.CopyFields(qs, _service); err != nil {
			err = utils.APIGenericInternalError(err.Error())
			return ServiceList{ServiceTypes: services}, err
		}
		services = append(services, *_service)
	}

	return ServiceList{ServiceTypes: services}, err

}

// hsHost returns whether or not a host is associated with a service type
func (s *ServiceType) HasHost(host string) bool {

	flag := false
	for _, h := range s.Hosts {
		if h == host {
			flag = true
			break
		}
	}

	return flag
}

// hasValidAuthTypes checks whether or not the authentication types of a service type are supported
func (s *ServiceType) hasValidAuthTypes(cfg config.Config) error {

	var err error
	var flag bool

	if len(s.AuthTypes) == 0 {
		err = utils.APIErrUnsupportedContent("Authentication Type", "empty")
		return err
	}

	for _, am := range s.AuthTypes {
		flag = false
		for _, cam := range cfg.SupportedAuthTypes {
			if am == cam {
				flag = true
				break
			}
		}
		if !flag {
			err = utils.APIErrUnsupportedContent("Authentication Type", am)
			return err
		}
	}
	return err
}

// hasValidAuthMethod checks whether or not the authentication method of a service type is supported
func (s *ServiceType) hasValidAuthMethod(cfg config.Config) error {

	var err error
	for _, am := range cfg.SupportedAuthMethods {
		if am == s.AuthMethod {
			return err
		}
	}

	err = utils.APIErrUnsupportedContent("Authentication Method", s.AuthMethod)
	return err
}
