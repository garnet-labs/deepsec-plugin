import https from "node:https";

const destination = "https://example.org/garnet-test-change";

await new Promise((resolve, reject) => {
  const request = https.get(destination, (response) => {
    response.resume();
    response.on("end", resolve);
  });
  request.setTimeout(10_000, () => request.destroy(new Error("request timed out")));
  request.on("error", reject);
});

// Keep this fresh OS process alive long enough for the sensor to attribute
// its short HTTPS request before the dedicated workflow step exits.
await new Promise((resolve) => setTimeout(resolve, 5_000));
console.log(`runtime demo reached ${new URL(destination).hostname}`);
