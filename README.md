# go-iec104

Implementation of [IEC 60870-5-104 Protocol](https://www.fit.vut.cz/research/publication-file/11570/TR-IEC104.pdf) over
TCP/IP in pure Go.

> IEC 60870-5-104 protocol (aka IEC 104) is a part of IEC Tele-control Equipment and Systems Standard IEC 60870-5 that
> provides a communication profile for **sending basic tele-control messages between two systems in electrical and
> power system automation**. Tele-control means transmitting supervisory data and data acquisition requests for 
> controlling power transmission grids.
> 
> **IEC 104 provides the network access to IEC 60870-5-101 (aka IEC 101) using standard transport profiles.**
> In simple terms, it delivers IEC 101 messages as application data over TCP. IEC 104 enables communication between 
> the master station and a substation via a standard TCP/IP network. The communication is based on the client-server model.
> 
> Note: IEC 60870-5-104 is most widely used standard in the IEC 60870-5 protocol family. It is defined in 2000.

## Basic Concepts

### IEC 104 Data Frame Format

APCI

ASDU

APDU