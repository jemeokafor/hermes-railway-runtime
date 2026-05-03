# Contributing

Thanks for helping improve the Hermes Railway runtime.

## Where to ask questions / get help

- GitHub Issues: https://github.com/jemeokafor/hermes-railway-runtime/issues

## Reporting bugs

Please include:

1) **Railway logs** around the failure
2) The output of:
   - `GET /healthz`
   - `GET /` from the runtime wrapper
3) Your Railway settings relevant to networking:
  - Public Networking enabled?
  - Domain target port set to **8080**?

## Pull requests

- Keep PRs small and focused (one fix per PR)
- Run locally:
  - `npm run lint`
  - `npm test`

If you’re making Dockerfile changes, please explain why they’re needed and how you tested.
