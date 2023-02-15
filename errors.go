package iec104

type errSingleCmdTerm struct{}

func (e errSingleCmdTerm) Error() string {
	return "termination of single command"
}

func IsErrSingleCmdTerm(err error) bool {
	_, ok := err.(errSingleCmdTerm)
	return ok
}

type errDoubleCmdTerm struct{}

func (e errDoubleCmdTerm) Error() string {
	return "termination of double command"
}

func IsErrDoubleCmdTerm(err error) bool {
	_, ok := err.(errDoubleCmdTerm)
	return ok
}
