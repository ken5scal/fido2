package main

type FidoError struct {
	Status                      string `json:"status"`
	ErrorMessage                string `json:"errorMessage"`
}
