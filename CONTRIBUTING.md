# Contributing

Contributions are welcome and encouraged.
There are several areas where help is needed/welcomed, including:

- Documentation
- Testing
- Code (Specifically around the networking and Raft consensus code)
- Frontend (Preferably in Vue by someone who actually knows what they're doing :stuck_out_tongue:)
- Design/Architecture

Protocol Buffers are used for all APIs and inter-node communcation.
They can be found in the [api](https://github.com/webmeshproj/api) repository.

If you'd like to play with the project on Kubernetes, there is a work-in-progress Operator in the [operator](https://github.com/webmeshproj/operator/) repository.
It already works fine on most clusters, and can be tested locally. However, it is lacking some features and is not yet ready for production use.
One core area where it still needs work is in the area of support for multiple cloud providers.
Currently, it can run in-cluster nodes on any provider, but out-of-cluster nodes can only be managed on GCP.
Support for other providers is planned, but not yet implemented.

Feel free to open an issue or PR if you have any questions or would like to contribute.

The [Plugin](https://github.com/webmeshproj/api/blob/main/proto/v1/plugin.proto) interface is the preferred destination for most functionality (not related to API calls) as it comes in.
I also hope to move a good chunk of the existing functionality into plugins as well.
Currently all the authentication mechanisms are implemented as plugins, but the rest of the functionality is still in the main codebase.
The current plugins and how they are used can all be found in the [plugins](./pkg/plugins/) directory.
