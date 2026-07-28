package dto

// Response is the minimal HTTP response shape the detector inspects.
type Response struct {
	Status int
	Body   string
}
