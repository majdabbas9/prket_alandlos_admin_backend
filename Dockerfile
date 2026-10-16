FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Commit this image was built from, reported by /health (CI passes it; local builds leave it empty)
ARG GIT_SHA=
ENV GIT_SHA=$GIT_SHA

# Expose port
EXPOSE 8081

# Command to run the server
CMD ["npm", "start"]
