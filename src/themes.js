// Цветовые темы Ivernarus1.
//
// Чтобы добавить свою тему, скопируйте один из блоков ниже и измените значения.
// Имя ключа (например 'light') используется внутренне; поле name отображается
// в выпадающем меню настроек. Тема автоматически появится после пересборки.

const THEMES = {

    light: {
        name: 'Светлая',
        vars: {
            '--bg':            '#fafbfc',
            '--bg-card':       '#ffffff',
            '--bg-hover':      '#f5f7fa',
            '--border':        '#e1e8ed',
            '--border-focus':  '#6b8cae',
            '--text-primary':  '#1a2332',
            '--text-secondary':'#5a6d7f',
            '--text-muted':    '#8b9ba8',
            '--accent':        '#4a7ba7',
            '--accent-hover':  '#3a6a95',
            '--danger':        '#d14343',
            '--danger-hover':  '#b93838',
            '--success':       '#3ea368',
            '--shadow-sm':     '0 1px 3px rgba(0,0,0,0.08)',
            '--shadow-md':     '0 4px 12px rgba(0,0,0,0.1)',
            '--shadow-lg':     '0 8px 24px rgba(0,0,0,0.12)',
            '--avatar-grad':   'linear-gradient(135deg, #6b8cae 0%, #4a7ba7 100%)',
        },
    },

    dark: {
        name: 'Тёмная',
        vars: {
            '--bg':            '#1a1d24',
            '--bg-card':       '#242832',
            '--bg-hover':      '#2d323e',
            '--border':        '#353a47',
            '--border-focus':  '#6ba0d4',
            '--text-primary':  '#e1e8ed',
            '--text-secondary':'#a8b3bd',
            '--text-muted':    '#6f7a85',
            '--accent':        '#6ba0d4',
            '--accent-hover':  '#83b5e3',
            '--danger':        '#e25656',
            '--danger-hover':  '#f06a6a',
            '--success':       '#4cb87f',
            '--shadow-sm':     '0 1px 3px rgba(0,0,0,0.4)',
            '--shadow-md':     '0 4px 12px rgba(0,0,0,0.5)',
            '--shadow-lg':     '0 8px 24px rgba(0,0,0,0.6)',
            '--avatar-grad':   'linear-gradient(135deg, #5a8fc7 0%, #3d6e9e 100%)',
        },
    },

    paper: {
        name: 'Бумажная',
        vars: {
            '--bg':            '#ede1c4',
            '--bg-card':       '#f7eedc',
            '--bg-hover':      '#e6d8b8',
            '--border':        '#cdb98e',
            '--border-focus':  '#8a6d2c',
            '--text-primary':  '#3d2e15',
            '--text-secondary':'#6b5530',
            '--text-muted':    '#9a8761',
            '--accent':        '#8a5a2c',
            '--accent-hover':  '#6f4720',
            '--danger':        '#a83e3e',
            '--danger-hover':  '#8d3232',
            '--success':       '#6b8a3a',
            '--shadow-sm':     '0 1px 3px rgba(94,68,30,0.12)',
            '--shadow-md':     '0 4px 12px rgba(94,68,30,0.18)',
            '--shadow-lg':     '0 8px 24px rgba(94,68,30,0.22)',
            '--avatar-grad':   'linear-gradient(135deg, #b08a52 0%, #8a5a2c 100%)',
        },
    },

};
