# Cloudflare Containers image: the app image (Dockerfile) with a lighter start command.
# Built and pushed to the Cloudflare registry by .github/workflows/docker-publish.yml;
# prket_alandlos_infra deploys it by tag.
# Runtime env/ports live in prket_alandlos_infra: containers/src/index.ts (Cloudflare) and
# containers/docker-compose.yml (local).
ARG BASE_IMAGE=ghcr.io/majdabbas9/prket_alandlos_admin_backend:latest
FROM ${BASE_IMAGE}

# `npm start` re-runs `tsc` (prestart) on every boot; dist/ is already built in the image.
CMD ["node", "dist/index.js"]
