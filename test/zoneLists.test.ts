import { describe, it, expect } from "vitest";
import { parseZoneScopedListText } from "../src/parsers/zoneLists";

describe("parseZoneScopedListText", () => {
  it("parses plain and zone-scoped entries", () => {
    const text = `
http.host eq "media-cdn1.seabuddy.co"
[seabuddy.co] http.host eq "a.com"
[!other.com] http.host eq "b.com"
# comment
`;
    const res = parseZoneScopedListText(text);
    expect(res).toHaveLength(3);
    expect(res[0]).toEqual({ expression: 'http.host eq "media-cdn1.seabuddy.co"', zone: null, exclude: false });
    expect(res[1]).toEqual({ expression: 'http.host eq "a.com"', zone: "seabuddy.co", exclude: false });
    expect(res[2]).toEqual({ expression: 'http.host eq "b.com"', zone: "other.com", exclude: true });
  });
});
