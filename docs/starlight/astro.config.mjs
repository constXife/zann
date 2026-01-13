import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: "https://constxife.github.io/zann/",
  base: "/zann/",
  integrations: [
    starlight({
      title: "Zann",
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/constXife/zann" },
      ],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { label: "Introduction", link: "/" },
            { label: "Install Guide", link: "/install/" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "API Reference", link: "/api/" },
          ],
        },
      ],
    }),
  ],
});
