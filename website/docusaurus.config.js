// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'ARGO API Authn',
  tagline: 'An authentication service for ARGO APIs',
  url: 'https://argoeu.github.io',
  baseUrl: '/argo-api-authn/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/grnet-favicon.png',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'ARGOeu', // Usually your GitHub org/user name.
  projectName: 'argo-api-authn', // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          // editUrl:
          //   'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
  /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
      ({
        navbar: {
          title: 'ARGO API Authn',
          logo: {
            alt: 'Logo',
            src: 'img/grnet-logo.png',
          },
          items: [
            {
              to: 'docs/',
              activeBasePath: 'docs',
              label: 'Docs',
              position: 'left',
            },
            {
              href: 'pathname:///openapi/explore',
              label: 'Explore the API',
              position: 'left',
            },
            {
              href: 'https://github.com/ARGOeu/argo-api-authn',
              label: 'GitHub',
              position: 'right',
            },
          ],
        },
        footer: {
          style: 'dark',
          logo: {
            alt: 'GRNET',
            src: 'img/grnet-logo.png',
            href: 'http://www.grnet.gr/',
          },
          links: [
            {
              title: 'Docs',
              items: [
                {
                  label: 'Introduction',
                  to: '/docs/',
                },
              ],
            },
            {
              title: 'More',
              items: [
                {
                  label: 'GitHub',
                  href: 'https://github.com/ARGOeu/argo-api-authn',
                },
              ],
            },
          ],
          copyright: `Copyright © ${new Date().getFullYear()} GRNET`,
        },
        prism: {
          theme: lightCodeTheme,
          darkTheme: darkCodeTheme,
        },
      }),
  themes: [
    [
      "@easyops-cn/docusaurus-search-local",
      {
        hashed: true,
        language: ["en", "zh"],
        highlightSearchTermsOnTargetPage: true,
        explicitSearchResultPath: true,
        indexBlog: false,
      },
    ],
  ],
};

module.exports = config;