# hpsdr - A Go library to support HPSDR radios including the Hermes-Lite 2

## Limitations
This is just a start on a real HPSDR library, but it works for simple receive-only uses. See https://github.com/jancona/hpsdrconnector for an example.

Current limitations include:
* Only the original HPSDR Protocol 1 is supported.
* It has only been tested with the [Hermes-Lite 2](https://github.com/softerhardware/Hermes-Lite2/wiki). Feel free to create [issues](https://github.com/jancona/hpsdr/issues) with reports of success or failure using other hardware. 
* Transmitting is not supported.
* The API is not yet stable.
