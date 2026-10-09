import { corsair } from "./corsair";

async function main(): Promise<void> {
  const result =
    await corsair.slack.api.messages.post({
      channel: "new-channel",
      text: "AI Guardian Corsair integration test ✅",
    });

  console.log(
    "CORSAIR SLACK POST: PASS"
  );

  console.log(result);
}

main().catch((error) => {
  console.error(
    "CORSAIR SLACK POST: FAIL"
  );

  console.error(error);

  process.exit(1);
});