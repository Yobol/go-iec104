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

### Data Types

#### Single Point Information

See the following table for decoding the status of a binary input accessed as a single point object.

| Single Point Info Qualifier | Digital Input Status |
| 0 (OFF)                     | OFF (Open)           |
| 1 (ON)                      | ON (Closed)          |

#### Double Point Information

Double point objects occupy two adjacent object addresses and should always be accessed by addressing the first address
of the pair. See the following table for decoding the status of binary inputs accessed as double point objects.

| Double Point Info Qualifier | Digital Input Status       |
|                             | DI1         | DI2          |
| 0 (Intermediate state)      | OFF (Open)  | OFF (Open)   |
| 1 (OFF)                     | ON (Closed) | OFF (Open)   |
| 1 (ON)                      | OFF (Open)  | ON (Closed)  |
| 1 (Intermediate state)      | ON (Closed) | ON (Closed)  |

#### Normalized Values

A normalized value represents per unit scaled reading of a measured value. Normalized values are transmitted as 16-bit
signed fixed point numbers (F16) in the range of [-1, 1-2^-15^].

#### Scaled Values

A scaled value represents the reading of a measured value scaled to a 16-bit integer number. Scaled values are transmitted
as 16-bit signed integer number (I16) in the range of [-32768, 32767].

### IEC 104 Data Frame Format

APDU

APCI

ASDU

### IEC 104 Basic Application Function

- Data acquisition - collecting data cyclically, upon change, or upon request:
  - In unbalanced transmission (upon request), the controlled outstation must always wait for a request from the 
    controlling station.
  - When balanced transmission (upon change) is used, the buffered data is transmitted by the controlled outstation
    to the controlling station without a delay.
- Event acquisition:
  - Events occur spontaneously at the application level of the controlled outstation. The transmission in balanced
    or unbalanced mode is similar to the data acquisition.
- Interrogation - used to update controlling station after an internal initialization:
  - The controlling station requests the controlled outstations to transmit the actual values of all their process variables.
- Clock synchronization:
  - After system initialization, the clocks are initially synchronized by the controlling station. After, the clocks
    are periodically resynchronized by transmission of a clock synchronization command.
- Command transmission - used to change the state of operational equipment:
  - A command may be initiated by an operator or by automatic supervisory procedures in the controlling station.
  - Two standard procedures for command transmission:
    - Direct command - used by the controlling station to immediately control operations in the controlled outstations.
      Permission and validity of the command is checked by the outstation.
    - Select and execute command - a two-step command that prepares a specified control operation in a control outstation,
      checks that the correct control operation is prepared, and execute the command. The preparation is checked by an
      operator or by an application procedure. The controlled outstation does not start the control operation until it
      has received the correct execute indication.
- Transmission of integrated totals:
  - Transmit values that are integrated over a specific time period using two methods:
    - Freeze-and-Read: acquisition of integrated totals
    - Clear-and-Read: acquisition of incremental information
- Changes in protocol and link parameters - when the link parameter are changed
- Acquisition of transmission delay - needed for time correction

### Transactional view on IEC 104 communication

## Analysis Samples

1. 68 0E 4E 14 7C 00 65 01 0A 00 0C 00 00 00 00 05
   | LPDU bytes | Explanation                                                                |
   | 68         | Start byte                                                                 |
   | 0E         | Length of the APDU = 14 bytes                                              |
   | 4E         | Send sequence number N(S) LSB, FrameType = 0 => I-Format                   |
   | 14         | Send sequence number N(S) MSB                                              |
   | 7C         | Receive sequence number N(R) LSB                                           |
   | 00         | Receive sequence number N(R) MSB                                           |
   | 65         | Type identification: C_CI_NA_1 (counter interrogation command)             |
   | 01         | SQ = 0, Number of objects = 1                                              |
   | 0A         | Cause of transmission = 10 (activation termination)                        |
   | 00         | Originator address = 0                                                     |
   | 0C 00      | Common ASDU address (2 octets) = 12 dec.                                   |
   | 00 00 00   | Object address (3 octets)                                                  |
   | 05         | Counter interrogation request qualifier = 5 (general counter interrogation)|

## References

1. [IEC 104 Packet Parser for Wireshark](https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-iec104.c)