import { defineConfig } from "deepsec/config";
import garnetPlugin from "./dist/index.js";

export default defineConfig({
  projects: [
    {
      id: "deepsec-plugin-demo",
      root: ".",
      githubUrl: "https://github.com/garnet-labs/deepsec-plugin/blob/main",
    },
  ],
  plugins: [
    garnetPlugin({
      apiToken: process.env.GARNET_API_TOKEN,
      baseUrl: process.env.GARNET_API_URL,
      repository: process.env.GITHUB_REPOSITORY ?? "garnet-labs/deepsec-plugin",
      workflowName: "CI",
    }),
  ],
});
