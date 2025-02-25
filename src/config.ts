import type {
  LicenseConfig,
  NavBarConfig,
  ProfileConfig,
  SiteConfig,
} from './types/config'
import { LinkPreset } from './types/config'

export const siteConfig: SiteConfig = {
  title: '黄豆安全实验室Blog',
  subtitle: 'Blog.HDSEC.CN',
  lang: 'zh_CN',         // 'en', 'zh_CN', 'zh_TW', 'ja', 'ko', 'es', 'th'
  themeColor: {
    hue: 250,         // Default hue for the theme color, from 0 to 360. e.g. red: 0, teal: 200, cyan: 250, pink: 345
    fixed: false,     // Hide the theme color picker for visitors
  },
  banner: {
    enable: true,
    src: 'assets/images/demo-banner.png',   // Relative to the /src directory. Relative to the /public directory if it starts with '/'
    position: 'center',      // Equivalent to object-position, only supports 'top', 'center', 'bottom'. 'center' by default
    credit: {
      enable: false,         // Display the credit text of the banner image
      text: 'H3l10 World!'           
    }
  },
  toc: {
    enable: true,           // Display the table of contents on the right side of the post
    depth: 2                // Maximum heading depth to show in the table, from 1 to 3
  },
  favicon: [    // Leave this array empty to use the default favicon
    // {
    //   src: '/favicon/icon.png',    // Path of the favicon, relative to the /public directory
    //   theme: 'light',              // (Optional) Either 'light' or 'dark', set only if you have different favicons for light and dark mode
    //   sizes: '32x32',              // (Optional) Size of the favicon, set only if you have favicons of different sizes
    // }
  ]
}

export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,
    LinkPreset.Archive,
    LinkPreset.About,
    {
      name: 'H0m3',
      url: 'https://www.hdsec.cn',     // Internal links should not include the base path, as it is automatically added
      external: true,                               // Show an external link icon and will open in a new tab
    },
  ],
}

export const profileConfig: ProfileConfig = {
  avatar: 'https://www.hdsec.cn/logo.jpg',  // Relative to the /src directory. Relative to the /public directory if it starts with '/'
  name: 'Hu@ng D0w',
  bio: '欲买桂花同载酒 终不似 少年游 便邀东风揽明月 春不许 再回头',
  links: [
    {
      name: 'Github',
      icon: 'fa6-brands:github', 
      url: 'https://github.com/Team-intN18-SoybeanSeclab',
    },
    {
      name: 'QQ群',
      icon: 'fa6-brands:qq', 
      url: 'http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=YJYbW2k-TFlv5VnbCx_pdbnDe2SLwzf2&authKey=oLKp6CLxuB24eEl%2FoAfMD2ZBkbwHwXB75%2BG%2B2itYUeJe4VSmN86SxdySkQjJQOFm&noverify=0&group_code=1028924504',
    },
  ],
}

export const licenseConfig: LicenseConfig = {
  enable: true,
  name: 'CC BY-NC-SA 4.0',
  url: 'https://creativecommons.org/licenses/by-nc-sa/4.0/',
}
