// @lexical/code imports Prism's language files, which expect a global `Prism`.
// Prism only sets one when loaded as a script, so the production bundle
// throws "Prism is not defined" without this. Import it before anything else.
import Prism from "prismjs";

(globalThis as { Prism?: typeof Prism }).Prism = Prism;
