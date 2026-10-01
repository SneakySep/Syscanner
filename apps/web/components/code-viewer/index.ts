/**
 * Vulnerability code viewer.
 *
 * A two-pane view of a source file with vulnerable lines highlighted in Monaco and an
 * interactive findings panel that scrolls the editor to the relevant line.
 *
 * CLIENT-ONLY. This barrel pulls in `monaco-setup`, which evaluates `monaco-editor`
 * at module load. A Server Component must import `./CodeViewerMount` directly — never
 * this barrel — or Monaco ends up in the server bundle.
 *
 * SECURITY NOTE — this component is presentation only. It is handed a code string and
 * finding metadata by its caller and contains no path handling of its own. When a real
 * source endpoint exists it MUST resolve paths against a fixed repository root and
 * reject `..`/absolute paths, because `filePath` originates from scanning a hostile
 * repository. See ARCHITECTURE.md §4.
 */
export { CodeViewerMount } from './CodeViewerMount';
export { VulnerabilityCodeViewer, type VulnerabilityCodeViewerProps } from './VulnerabilityCodeViewer';
export { VulnerabilitiesSidebar, type VulnerabilitiesSidebarProps } from './VulnerabilitiesSidebar';
export {
  buildDecorations,
  clampFindingToDocument,
  DECORATION_CLASSES,
  DECORATION_GLYPH_CLASSES,
  lineForFinding,
  MAX_DECORATIONS,
  severityCounts,
  severityRank,
  sortFindings,
  toPresentationSeverity,
  type ViewerFinding,
} from './decorations';
export { sanitizeLanguage, setupMonaco } from './monaco-setup';