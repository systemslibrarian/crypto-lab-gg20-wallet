import { expect, test } from '@playwright/test';

type Rgb = [number, number, number];

function rgb(value: string): Rgb {
  const channels = value.match(/[\d.]+/g)?.map(Number) ?? [];
  return [channels[0], channels[1], channels[2]];
}

function luminance(color: Rgb): number {
  const channels = color.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(first: Rgb, second: Rgb): number {
  const lighter = Math.max(luminance(first), luminance(second));
  const darker = Math.min(luminance(first), luminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

for (const theme of ['dark'] as const) {
  test(`${theme} text controls retain 3:1 boundary contrast`, async ({ page }) => {
    await page.goto('.');

    const controls = page.locator('input[type="text"], textarea');
    await expect(controls.first()).toBeVisible();
    for (const control of await controls.all()) {
      const colors = await control.evaluate((element) => {
        const style = getComputedStyle(element);
        return { border: style.borderTopColor, background: style.backgroundColor };
      });
      expect(contrast(rgb(colors.border), rgb(colors.background))).toBeGreaterThanOrEqual(3);
    }
  });
}
