# OpenIddict.Conformance

This repository **contains an OpenIddict-based authorization server specially designed to be used with the [OpenID Connect Provider Certification tool](https://op.certification.openid.net:60000/)** and demonstrate that OpenIddict can be easily used in a certified implementation.

> Note: to allow executing the certification tests as fast as possible, this demo server doesn't include any membership
or consent feature (two hardcoded identities are proposed for tests that require switching between identities).

## Why is OpenIddict not certified?

Unlike many other identity providers, **OpenIddict is not a turnkey solution but a framework that requires writing custom code**
to be operational (basically, an authorization controller), making it a poor candidate for the certification program.

While we could of course submit a reference implementation like the one contained in this repository,
**this wouldn't guarantee that implementations deployed by OpenIddict users would themselves be standard-compliant.**

Instead, **developers are encouraged to execute the conformance tests against their own deployment** once they've implemented their own authorization logic.

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/openiddict](https://stackoverflow.com/questions/tagged/openiddict)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
