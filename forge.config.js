const path = require('path');

module.exports = {
  packagerConfig: {
    name: 'AgenticTM',
    executableName: 'agentictm',
    asar: false,
    icon: path.resolve(__dirname, 'electron', 'icons', 'icon'),
    extraResource: [
      path.resolve(__dirname, 'agentictm'),
      path.resolve(__dirname, 'run.py'),
      path.resolve(__dirname, 'cli.py'),
      path.resolve(__dirname, 'main.py'),
      path.resolve(__dirname, 'config.json'),
      path.resolve(__dirname, 'requirements.txt'),
      path.resolve(__dirname, 'pyproject.toml'),
      path.resolve(__dirname, 'knowledge_base'),
    ],
    ignore: [
      /^\/\.venv/,
      /^\/\.git/,
      /^\/\.github/,
      /^\/\.cursor/,
      /^\/output/,
      /^\/data/,
      /^\/docs/,
      /^\/tests/,
      /^\/rag/,
      /^\/reporte\.pdf$/,
      /^\/\.dockerignore$/,
      /^\/Dockerfile$/,
      /^\/docker-compose\.yml$/,
    ],
  },
  makers: [
    {
      name: '@electron-forge/maker-zip',
      platforms: ['darwin', 'linux', 'win32'],
    },
    {
      name: '@electron-forge/maker-dmg',
      config: {
        format: 'ULFO',
        background: path.resolve(__dirname, 'electron', 'icons', 'dmg-bg.png'),
        icon: path.resolve(__dirname, 'electron', 'icons', 'icon.icns'),
      },
    },
    {
      name: '@electron-forge/maker-squirrel',
      config: {
        name: 'AgenticTM',
        setupIcon: path.resolve(__dirname, 'electron', 'icons', 'icon.ico'),
      },
    },
    {
      name: '@electron-forge/maker-deb',
      config: {
        options: {
          maintainer: 'AgenticTM',
          homepage: 'https://github.com/PhiloCyber/agent-threat-modeler',
          icon: path.resolve(__dirname, 'electron', 'icons', 'icon.png'),
        },
      },
    },
    {
      name: '@electron-forge/maker-rpm',
      config: {
        options: {
          homepage: 'https://github.com/PhiloCyber/agent-threat-modeler',
          icon: path.resolve(__dirname, 'electron', 'icons', 'icon.png'),
        },
      },
    },
  ],
};
