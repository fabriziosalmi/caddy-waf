import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import './custom.css'

// The stock theme, restyled through CSS variables only. No component
// overrides: they are what make a docs site expensive to keep working across
// VitePress upgrades, and nothing here needs one.
export default DefaultTheme satisfies Theme
