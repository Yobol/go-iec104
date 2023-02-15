package iec104

type ClientHandler interface {
	GeneralInterrogationHandler(apdu *APDU) error
	CounterInterrogationHandler(apdu *APDU) error
	ClockSynchronizationHandler(apdu *APDU) error
	TestCommandHandler(apdu *APDU) error
	ReadCommandHandler(apdu *APDU) error
	ResetProcessCommandHandler(apdu *APDU) error
	DelayAcquisitionCommandHandler(apdu *APDU) error

	APDUHandler(apdu *APDU) error
}
