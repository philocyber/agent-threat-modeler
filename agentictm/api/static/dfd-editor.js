/* ═══════════════════════════════════════════════════════════════════
   DFD ThreatCanvas — Post-Analysis Interactive Threat Diagram
   Inspired by SecureFlag ThreatCanvas
   ═══════════════════════════════════════════════════════════════════

   This editor is activated ONLY after analysis completes.
   It auto-builds the DFD from the analysis result (mermaid_dfd,
   components, data_flows, trust_boundaries) and displays threats
   grouped by component in a sidebar panel.

   Key capabilities:
   - Auto-construct DFD from parsed architecture
   - Threat sidebar: threats grouped by component, filterable
   - Click component → highlight threats; click threat → highlight node
   - Threat severity badges on diagram nodes
   - Drag & rearrange nodes, zoom/pan
   - Bidirectional Mermaid code sync
   - Export to architecture description
   ═══════════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';

  let _idSeq = 0;
  function uid(prefix = 'dfd') {
    return `${prefix}_${Date.now().toString(36)}_${(++_idSeq).toString(36)}`;
  }

  const NODE_DEFAULTS = {
    process: { width: 140, height: 60, label: 'Process', scope: 'internal' },
    external_entity: { width: 130, height: 55, label: 'External Entity', scope: 'external' },
    data_store: { width: 140, height: 50, label: 'Data Store', scope: 'internal' },
  };

  /* ═══════════════════════════════════
     DFDEditor Class
     ═══════════════════════════════════ */
  class DFDEditor {
    constructor(containerId) {
      this.container = document.getElementById(containerId);
      if (!this.container) throw new Error(`DFD Editor: container #${containerId} not found`);

      // Diagram state
      this.nodes = [];
      this.edges = [];
      this.boundaries = [];

      // Threat data (from analysis)
      this.threats = [];
      this.analysisResult = null;

      // Interaction state
      this.selectedItems = new Set();
      this.highlightedNodeId = null;
      this.selectedThreatId = null;
      this.activeToolType = 'select';
      this.zoom = 1;
      this.panX = 0;
      this.panY = 0;
      this.gridSize = 20;
      this.snapToGrid = true;
      this.edgeRouting = 'orthogonal'; // 'straight' | 'orthogonal' | 'curved'
      this._undoStack = [];
      this._redoStack = [];
      this._dragging = null;
      this._panning = false;
      this._connecting = null;
      this._tempLine = null;
      this._contextMenu = null;
      this._propertiesCollapsed = false;
      this._threatSidebarCollapsed = false;
      this._activeFilter = 'all';
      this._searchQuery = '';
      this._inlineEditor = null;
      this._rubberBand = null;
      this._rubberBandStart = null;

      this._icons = this._buildIcons();
      this._build();
      this._bindEvents();
      this._render();
    }

    /* ═══════════════════════════════════
       Build DOM — 3-column layout
       ═══════════════════════════════════ */
    _build() {
      this.container.innerHTML = '';
      this.container.className = 'dfd-editor-wrapper';

      // Toolbar
      this._toolbar = this._createToolbar();
      this.container.appendChild(this._toolbar);

      // Body: threat sidebar | canvas | properties
      this._body = document.createElement('div');
      this._body.className = 'dfd-editor-body';

      this._threatSidebar = this._createThreatSidebar();
      this._canvasContainer = this._createCanvas();
      this._properties = this._createProperties();

      this._body.appendChild(this._threatSidebar);
      this._body.appendChild(this._canvasContainer);
      this._body.appendChild(this._properties);
      this.container.appendChild(this._body);

      // Bottom panel (Mermaid / Description)
      this._bottomPanel = this._createBottomPanel();
      this.container.appendChild(this._bottomPanel);
    }

    _createToolbar() {
      const toolbar = document.createElement('div');
      toolbar.className = 'dfd-toolbar';

      // Pointer / connect tools
      const toolsGroup = this._makeToolbarGroup([
        { id: 'select', icon: this._icons.cursor, label: 'Select', shortcut: 'V' },
        { id: 'connect', icon: this._icons.connect, label: 'Connect', shortcut: 'C' },
      ]);

      // Add components group
      const addGroup = this._makeToolbarGroup([
        { id: 'process', icon: this._icons.process, label: 'Process', shortcut: 'P' },
        { id: 'external_entity', icon: this._icons.external, label: 'External', shortcut: 'E' },
        { id: 'data_store', icon: this._icons.dataStore, label: 'Data Store', shortcut: 'D' },
        { id: 'boundary', icon: this._icons.boundary, label: 'Boundary', shortcut: 'B' },
      ]);

      // Actions
      const actionsGroup = document.createElement('div');
      actionsGroup.className = 'dfd-toolbar-group';
      actionsGroup.append(
        this._makeToolBtn('undo', this._icons.undo, 'Undo', () => this.undo()),
        this._makeToolBtn('redo', this._icons.redo, 'Redo', () => this.redo()),
        this._makeToolBtn('delete', this._icons.trash, 'Delete', () => this.deleteSelected(), 'dfd-btn-danger'),
      );

      // View
      const viewGroup = document.createElement('div');
      viewGroup.className = 'dfd-toolbar-group';
      const gridBtn = this._makeToolBtn('grid', this._icons.grid, 'Snap', () => this._toggleGrid());
      gridBtn.classList.toggle('active', this.snapToGrid);
      this._gridBtn = gridBtn;
      viewGroup.append(
        gridBtn,
        this._makeToolBtn('fit', this._icons.fit, 'Fit View', () => this.fitToView()),
      );

      // Layout & Edge routing group
      const layoutGroup = document.createElement('div');
      layoutGroup.className = 'dfd-toolbar-group';
      const routeBtn = this._makeToolBtn('route', this._icons.route, 'Edge Routing', () => this._cycleEdgeRouting());
      routeBtn.title = 'Edge: orthogonal';
      this._routeBtn = routeBtn;
      layoutGroup.append(
        this._makeToolBtn('forceLayout', this._icons.force, 'Smart Layout', () => this._forceLayout()),
        routeBtn,
      );

      // Export group
      const exportGroup = document.createElement('div');
      exportGroup.className = 'dfd-toolbar-group';
      exportGroup.append(
        this._makeToolBtn('exportSvg', this._icons.exportSvg, 'Export SVG', () => this.exportSVG()),
        this._makeToolBtn('exportPng', this._icons.exportPng, 'Export PNG', () => this.exportPNG()),
      );

      // Threat sidebar toggle
      const sidebarToggle = document.createElement('button');
      sidebarToggle.className = 'dfd-sidebar-toggle';
      sidebarToggle.title = 'Toggle threat panel';
      sidebarToggle.innerHTML = '☰';
      sidebarToggle.addEventListener('click', () => this._toggleThreatSidebar());

      toolbar.append(sidebarToggle, toolsGroup, addGroup, actionsGroup, viewGroup, layoutGroup, exportGroup);
      return toolbar;
    }

    _makeToolbarGroup(tools) {
      const group = document.createElement('div');
      group.className = 'dfd-toolbar-group';
      for (const t of tools) {
        const btn = this._makeToolBtn(t.id, t.icon, t.label, () => this._setTool(t.id));
        btn.dataset.tool = t.id;
        if (t.id === this.activeToolType) btn.classList.add('active');
        group.appendChild(btn);
      }
      return group;
    }

    _makeToolBtn(id, iconSvg, label, onClick, extraClass = '') {
      const btn = document.createElement('button');
      btn.className = 'dfd-tool-btn' + (extraClass ? ' ' + extraClass : '');
      btn.innerHTML = iconSvg + `<span>${label}</span>`;
      btn.title = label;
      btn.addEventListener('click', onClick);
      return btn;
    }

    /* ── Threat Sidebar (Left Panel) ── */
    _createThreatSidebar() {
      const sidebar = document.createElement('div');
      sidebar.className = 'dfd-threat-sidebar';

      // Header
      const header = document.createElement('div');
      header.className = 'dfd-threat-sidebar-header';

      const titleRow = document.createElement('div');
      titleRow.className = 'dfd-threat-sidebar-title';
      titleRow.innerHTML = `<span>Threats</span><span class="badge" id="dfdThreatCount">0</span>`;
      header.appendChild(titleRow);

      // Filters
      const filters = document.createElement('div');
      filters.className = 'dfd-threat-filter';
      const filterOpts = [
        { id: 'all', label: 'All' },
        { id: 'Critical', label: 'Critical' },
        { id: 'High', label: 'High' },
        { id: 'Medium', label: 'Med' },
        { id: 'Low', label: 'Low' },
      ];
      for (const f of filterOpts) {
        const btn = document.createElement('button');
        btn.className = 'dfd-threat-filter-btn' + (f.id === 'all' ? ' active' : '');
        btn.textContent = f.label;
        btn.dataset.filter = f.id;
        btn.addEventListener('click', () => this._setThreatFilter(f.id));
        filters.appendChild(btn);
      }
      header.appendChild(filters);

      // Search
      const search = document.createElement('input');
      search.className = 'dfd-threat-search';
      search.type = 'text';
      search.placeholder = 'Search threats...';
      search.addEventListener('input', (e) => {
        this._searchQuery = e.target.value.toLowerCase();
        this._renderThreatList();
      });
      header.appendChild(search);

      sidebar.appendChild(header);

      // Threat list container
      this._threatListEl = document.createElement('div');
      this._threatListEl.className = 'dfd-threat-list';
      this._threatListEl.innerHTML = '<div class="dfd-props-empty">Run an analysis to see threats mapped to components</div>';
      sidebar.appendChild(this._threatListEl);

      return sidebar;
    }

    /* ── Canvas ── */
    _createCanvas() {
      const container = document.createElement('div');
      container.className = 'dfd-canvas-container';
      container.id = 'dfdCanvasContainer';

      const svg = document.createElementNS(SVG_NS, 'svg');
      svg.setAttribute('class', 'dfd-canvas-svg');
      svg.setAttribute('xmlns', SVG_NS);

      // Defs
      const defs = document.createElementNS(SVG_NS, 'defs');

      // Arrowhead
      const marker = document.createElementNS(SVG_NS, 'marker');
      marker.setAttribute('id', 'arrowhead');
      marker.setAttribute('markerWidth', '10');
      marker.setAttribute('markerHeight', '7');
      marker.setAttribute('refX', '9');
      marker.setAttribute('refY', '3.5');
      marker.setAttribute('orient', 'auto');
      marker.setAttribute('markerUnits', 'strokeWidth');
      const arrow = document.createElementNS(SVG_NS, 'polygon');
      arrow.setAttribute('points', '0 0, 10 3.5, 0 7');
      arrow.setAttribute('fill', '#6a6a6a');
      marker.appendChild(arrow);
      defs.appendChild(marker);

      // Arrowhead selected
      const markerS = document.createElementNS(SVG_NS, 'marker');
      markerS.setAttribute('id', 'arrowhead-selected');
      markerS.setAttribute('markerWidth', '10');
      markerS.setAttribute('markerHeight', '7');
      markerS.setAttribute('refX', '9');
      markerS.setAttribute('refY', '3.5');
      markerS.setAttribute('orient', 'auto');
      markerS.setAttribute('markerUnits', 'strokeWidth');
      const arrowS = document.createElementNS(SVG_NS, 'polygon');
      arrowS.setAttribute('points', '0 0, 10 3.5, 0 7');
      arrowS.setAttribute('fill', '#28D07D');
      markerS.appendChild(arrowS);
      defs.appendChild(markerS);

      // Grid pattern
      const gridP = document.createElementNS(SVG_NS, 'pattern');
      gridP.setAttribute('id', 'dfd-grid');
      gridP.setAttribute('width', '20');
      gridP.setAttribute('height', '20');
      gridP.setAttribute('patternUnits', 'userSpaceOnUse');
      const dot = document.createElementNS(SVG_NS, 'circle');
      dot.setAttribute('cx', '1');
      dot.setAttribute('cy', '1');
      dot.setAttribute('r', '0.5');
      dot.setAttribute('fill', 'rgba(255,255,255,0.06)');
      gridP.appendChild(dot);
      defs.appendChild(gridP);
      svg.appendChild(defs);

      // Grid background
      const gridBg = document.createElementNS(SVG_NS, 'rect');
      gridBg.setAttribute('width', '10000');
      gridBg.setAttribute('height', '10000');
      gridBg.setAttribute('x', '-5000');
      gridBg.setAttribute('y', '-5000');
      gridBg.setAttribute('fill', 'url(#dfd-grid)');
      gridBg.setAttribute('class', 'dfd-canvas-bg');

      this._gridBg = gridBg;
      this._layerBoundaries = document.createElementNS(SVG_NS, 'g');
      this._layerEdges = document.createElementNS(SVG_NS, 'g');
      this._layerNodes = document.createElementNS(SVG_NS, 'g');
      this._layerOverlay = document.createElementNS(SVG_NS, 'g');

      this._transformGroup = document.createElementNS(SVG_NS, 'g');
      this._transformGroup.setAttribute('class', 'dfd-transform-group');
      this._transformGroup.append(gridBg, this._layerBoundaries, this._layerEdges, this._layerNodes, this._layerOverlay);
      svg.appendChild(this._transformGroup);

      this._svg = svg;
      container.appendChild(svg);

      // Empty state
      this._emptyState = document.createElement('div');
      this._emptyState.className = 'dfd-empty-state';
      this._emptyState.innerHTML = `
        <svg class="dfd-empty-icon" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="8" y="20" width="20" height="14" rx="3"/>
          <rect x="36" y="20" width="20" height="14" rx="3"/>
          <line x1="28" y1="27" x2="36" y2="27" stroke-dasharray="3 2"/>
          <rect x="22" y="42" width="20" height="14" rx="3"/>
          <line x1="18" y1="34" x2="28" y2="42" stroke-dasharray="3 2"/>
          <line x1="46" y1="34" x2="38" y2="42" stroke-dasharray="3 2"/>
        </svg>
        <div class="dfd-empty-title">Threat Model Diagram</div>
        <div class="dfd-empty-desc">Run an analysis to auto-generate the interactive threat diagram</div>
      `;
      container.appendChild(this._emptyState);

      // Toast
      this._toast = document.createElement('div');
      this._toast.className = 'dfd-toast';
      container.appendChild(this._toast);

      // Minimap
      const minimap = this._buildMinimap();
      container.appendChild(minimap);

      // Zoom controls
      const zoomCtrl = document.createElement('div');
      zoomCtrl.className = 'dfd-zoom-controls';
      zoomCtrl.innerHTML = `
        <button class="dfd-zoom-btn" title="Zoom In" id="dfdZoomIn">+</button>
        <div class="dfd-zoom-level" id="dfdZoomLevel">100%</div>
        <button class="dfd-zoom-btn" title="Zoom Out" id="dfdZoomOut">−</button>
        <button class="dfd-zoom-btn" title="Reset" id="dfdZoomReset" style="font-size:11px;margin-top:4px">⟲</button>
      `;
      container.appendChild(zoomCtrl);

      return container;
    }

    /* ── Properties Panel (Right) ── */
    _createProperties() {
      const panel = document.createElement('div');
      panel.className = 'dfd-properties';

      const header = document.createElement('div');
      header.className = 'dfd-props-header';
      header.innerHTML = `
        <span class="dfd-props-title">Properties</span>
        <button class="dfd-props-close" title="Close" id="dfdPropsClose">
          <svg width="14" height="14" viewBox="0 0 14 14"><path d="M3.5 3.5l7 7M10.5 3.5l-7 7" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>
        </button>
      `;
      panel.appendChild(header);

      this._propsBody = document.createElement('div');
      this._propsBody.className = 'dfd-props-body';
      this._propsBody.innerHTML = '<div class="dfd-props-empty">Select a component to edit its properties</div>';
      panel.appendChild(this._propsBody);

      return panel;
    }

    /* ── Bottom Panel ── */
    _createBottomPanel() {
      const panel = document.createElement('div');
      panel.className = 'dfd-bottom-panel';
      panel.style.height = '180px';

      const tabs = document.createElement('div');
      tabs.className = 'dfd-bottom-tabs';
      tabs.innerHTML = `
        <div class="dfd-bottom-tab active" data-btab="mermaid">Mermaid Code</div>
        <div class="dfd-bottom-tab" data-btab="description">Architecture Description</div>
        <button class="dfd-bottom-toggle" id="dfdBottomToggle">▲ Toggle</button>
      `;
      panel.appendChild(tabs);

      const content = document.createElement('div');
      content.className = 'dfd-bottom-content';

      this._mermaidEditor = document.createElement('textarea');
      this._mermaidEditor.className = 'dfd-code-editor';
      this._mermaidEditor.placeholder = 'Mermaid code will auto-generate from diagram...';
      this._mermaidEditor.spellcheck = false;

      this._descriptionEditor = document.createElement('textarea');
      this._descriptionEditor.className = 'dfd-description-area';
      this._descriptionEditor.placeholder = 'Architecture description auto-generated from diagram...';
      this._descriptionEditor.style.display = 'none';

      content.appendChild(this._mermaidEditor);
      content.appendChild(this._descriptionEditor);
      panel.appendChild(content);

      return panel;
    }

    /* ═══════════════════════════════════
       Event Binding
       ═══════════════════════════════════ */
    _bindEvents() {
      const svg = this._svg;
      const container = this._canvasContainer;

      svg.addEventListener('mousedown', (e) => this._onMouseDown(e));
      svg.addEventListener('mousemove', (e) => this._onMouseMove(e));
      svg.addEventListener('mouseup', (e) => this._onMouseUp(e));
      svg.addEventListener('dblclick', (e) => this._onDblClick(e));
      svg.addEventListener('contextmenu', (e) => this._onContextMenu(e));
      container.addEventListener('wheel', (e) => this._onWheel(e), { passive: false });

      container.querySelector('#dfdZoomIn')?.addEventListener('click', () => this._setZoom(this.zoom + 0.1));
      container.querySelector('#dfdZoomOut')?.addEventListener('click', () => this._setZoom(this.zoom - 0.1));
      container.querySelector('#dfdZoomReset')?.addEventListener('click', () => { this._setZoom(1); this.panX = 0; this.panY = 0; this._applyTransform(); });

      document.addEventListener('keydown', (e) => this._onKeyDown(e));
      document.addEventListener('click', () => this._hideContextMenu());

      // Bottom panel tabs
      this._bottomPanel.querySelectorAll('.dfd-bottom-tab').forEach(tab => {
        tab.addEventListener('click', () => this._switchBottomTab(tab.dataset.btab));
      });
      this._bottomPanel.querySelector('#dfdBottomToggle')?.addEventListener('click', () => this._toggleBottomPanel());

      // Properties close
      this._properties.querySelector('#dfdPropsClose')?.addEventListener('click', () => {
        this._propertiesCollapsed = true;
        this._properties.classList.add('collapsed');
      });

      // Mermaid editor input (bidirectional)
      this._mermaidEditor.addEventListener('input', () => {
        clearTimeout(this._mermaidDebounce);
        this._mermaidDebounce = setTimeout(() => this._parseMermaidInput(), 600);
      });

      // Canvas drag & drop for adding nodes
      this._canvasContainer.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    }

    /* ═══════════════════════════════════
       Mouse / Interaction
       ═══════════════════════════════════ */
    _svgPoint(e) {
      const rect = this._svg.getBoundingClientRect();
      return {
        x: (e.clientX - rect.left - this.panX) / this.zoom,
        y: (e.clientY - rect.top - this.panY) / this.zoom,
      };
    }

    _snap(val) { return this.snapToGrid ? Math.round(val / this.gridSize) * this.gridSize : val; }

    _onMouseDown(e) {
      if (e.button === 2) return;
      const pt = this._svgPoint(e);

      const nodeEl = e.target.closest('.dfd-node');
      const edgeEl = e.target.closest('.dfd-edge');
      const boundaryEl = e.target.closest('.dfd-boundary');

      if (this.activeToolType === 'connect' && nodeEl) {
        const nodeId = nodeEl.dataset.nodeId;
        this._connecting = { sourceId: nodeId, startPt: pt };
        this._tempLine = document.createElementNS(SVG_NS, 'line');
        this._tempLine.setAttribute('x1', pt.x);
        this._tempLine.setAttribute('y1', pt.y);
        this._tempLine.setAttribute('x2', pt.x);
        this._tempLine.setAttribute('y2', pt.y);
        this._tempLine.setAttribute('stroke', '#28D07D');
        this._tempLine.setAttribute('stroke-width', '2');
        this._tempLine.setAttribute('stroke-dasharray', '6 3');
        this._layerOverlay.appendChild(this._tempLine);
        return;
      }

      if (['process', 'external_entity', 'data_store'].includes(this.activeToolType)) {
        this._addNode(this.activeToolType, this._snap(pt.x), this._snap(pt.y));
        this._setTool('select');
        return;
      }

      if (this.activeToolType === 'boundary') {
        this._addBoundary(this._snap(pt.x), this._snap(pt.y));
        this._setTool('select');
        return;
      }

      if (nodeEl) {
        const nodeId = nodeEl.dataset.nodeId;
        this._selectItem(nodeId, e.shiftKey);
        const node = this._findNode(nodeId);
        if (node) {
          this._dragging = { type: 'node', id: nodeId, ox: pt.x - node.x, oy: pt.y - node.y };
        }
        // Highlight threats for this component
        this._highlightComponentThreats(nodeId);
        return;
      }

      if (edgeEl) {
        this._selectItem(edgeEl.dataset.edgeId, e.shiftKey);
        return;
      }

      if (boundaryEl) {
        const bId = boundaryEl.dataset.boundaryId;
        this._selectItem(bId, e.shiftKey);
        const b = this._findBoundary(bId);
        if (b) {
          this._dragging = { type: 'boundary', id: bId, ox: pt.x - b.x, oy: pt.y - b.y };
        }
        return;
      }

      // Empty click — start panning or deselect
      if (!e.shiftKey) {
        this.selectedItems.clear();
        this._clearHighlights();
        this._render();
        this._updateProperties();
      }
      this._panning = true;
      this._panStart = { x: e.clientX - this.panX, y: e.clientY - this.panY };
    }

    _onMouseMove(e) {
      if (this._connecting && this._tempLine) {
        const pt = this._svgPoint(e);
        this._tempLine.setAttribute('x2', pt.x);
        this._tempLine.setAttribute('y2', pt.y);
        return;
      }

      if (this._dragging) {
        const pt = this._svgPoint(e);
        if (this._dragging.type === 'node') {
          const node = this._findNode(this._dragging.id);
          if (node) {
            node.x = this._snap(pt.x - this._dragging.ox);
            node.y = this._snap(pt.y - this._dragging.oy);
            this._render();
          }
        } else if (this._dragging.type === 'boundary') {
          const b = this._findBoundary(this._dragging.id);
          if (b) {
            b.x = this._snap(pt.x - this._dragging.ox);
            b.y = this._snap(pt.y - this._dragging.oy);
            this._render();
          }
        }
        return;
      }

      if (this._panning) {
        this.panX = e.clientX - this._panStart.x;
        this.panY = e.clientY - this._panStart.y;
        this._applyTransform();
      }
    }

    _onMouseUp(e) {
      if (this._connecting) {
        const nodeEl = e.target.closest('.dfd-node');
        if (nodeEl && nodeEl.dataset.nodeId !== this._connecting.sourceId) {
          this._addEdge(this._connecting.sourceId, nodeEl.dataset.nodeId);
        }
        if (this._tempLine) { this._tempLine.remove(); this._tempLine = null; }
        this._connecting = null;
        return;
      }

      if (this._dragging) {
        this._dragging = null;
        this._updateMermaidCode();
        this._updateDescription();
        return;
      }

      this._panning = false;
    }

    _onDblClick(e) {
      const nodeEl = e.target.closest('.dfd-node');
      if (nodeEl) { this._editNodeLabel(nodeEl.dataset.nodeId); return; }
      const boundaryEl = e.target.closest('.dfd-boundary');
      if (boundaryEl) { this._editBoundaryLabel(boundaryEl.dataset.boundaryId); return; }
      const edgeEl = e.target.closest('.dfd-edge');
      if (edgeEl) { this._editEdgeLabel(edgeEl.dataset.edgeId); return; }
    }

    _onContextMenu(e) {
      e.preventDefault();
      const pt = this._svgPoint(e);
      const nodeEl = e.target.closest('.dfd-node');
      const edgeEl = e.target.closest('.dfd-edge');
      const items = [];

      if (nodeEl) {
        const nid = nodeEl.dataset.nodeId;
        this._selectItem(nid, false);
        items.push(
          { label: 'Edit Label', action: () => this._editNodeLabel(nid) },
          { label: 'Duplicate', action: () => this._duplicateNode(nid) },
          { separator: true },
          { label: 'Delete', action: () => this._deleteNode(nid), danger: true },
        );
      } else if (edgeEl) {
        const eid = edgeEl.dataset.edgeId;
        this._selectItem(eid, false);
        items.push(
          { label: 'Edit Label', action: () => this._editEdgeLabel(eid) },
          { label: 'Reverse', action: () => this._reverseEdge(eid) },
          { separator: true },
          { label: 'Delete', action: () => this._deleteEdge(eid), danger: true },
        );
      } else {
        items.push(
          { label: 'Add Process', action: () => this._addNode('process', pt.x, pt.y) },
          { label: 'Add External Entity', action: () => this._addNode('external_entity', pt.x, pt.y) },
          { label: 'Add Data Store', action: () => this._addNode('data_store', pt.x, pt.y) },
          { separator: true },
          { label: 'Fit to View', action: () => this.fitToView() },
        );
      }

      this._showContextMenu(e.clientX, e.clientY, items);
    }

    _onWheel(e) {
      e.preventDefault();
      const delta = -e.deltaY * 0.001;
      const newZoom = Math.max(0.2, Math.min(3, this.zoom + delta));
      const rect = this._svg.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const scale = newZoom / this.zoom;
      this.panX = mx - (mx - this.panX) * scale;
      this.panY = my - (my - this.panY) * scale;
      this.zoom = newZoom;
      this._applyTransform();
      this._updateZoomDisplay();
    }

    _onKeyDown(e) {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
      if (!this.container.closest('.panel.active')) return;

      const key = e.key.toLowerCase();
      const ctrl = e.ctrlKey || e.metaKey;

      if (key === 'delete' || key === 'backspace') { this.deleteSelected(); e.preventDefault(); }
      else if (ctrl && key === 'z') { e.shiftKey ? this.redo() : this.undo(); e.preventDefault(); }
      else if (ctrl && key === 'y') { this.redo(); e.preventDefault(); }
      else if (key === 'v') this._setTool('select');
      else if (key === 'c' && !ctrl) this._setTool('connect');
      else if (key === 'p') this._setTool('process');
      else if (key === 'e') this._setTool('external_entity');
      else if (key === 'd' && !ctrl) this._setTool('data_store');
      else if (key === 'b') this._setTool('boundary');
      else if (key === 'escape') { this._setTool('select'); this.selectedItems.clear(); this._clearHighlights(); this._render(); }
    }

    /* ═══════════════════════════════════
       Tool Selection
       ═══════════════════════════════════ */
    _setTool(type) {
      this.activeToolType = type;
      this._toolbar.querySelectorAll('[data-tool]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tool === type);
      });
      this._svg.classList.toggle('tool-connect', type === 'connect');
    }

    _toggleGrid() {
      this.snapToGrid = !this.snapToGrid;
      this._gridBtn.classList.toggle('active', this.snapToGrid);
    }

    /* ═══════════════════════════════════
       Node / Edge / Boundary Operations
       ═══════════════════════════════════ */
    _saveUndo() {
      this._undoStack.push({
        nodes: JSON.parse(JSON.stringify(this.nodes)),
        edges: JSON.parse(JSON.stringify(this.edges)),
        boundaries: JSON.parse(JSON.stringify(this.boundaries)),
      });
      if (this._undoStack.length > 50) this._undoStack.shift();
      this._redoStack = [];
    }

    undo() {
      if (this._undoStack.length === 0) return;
      this._redoStack.push({
        nodes: JSON.parse(JSON.stringify(this.nodes)),
        edges: JSON.parse(JSON.stringify(this.edges)),
        boundaries: JSON.parse(JSON.stringify(this.boundaries)),
      });
      const state = this._undoStack.pop();
      this.nodes = state.nodes;
      this.edges = state.edges;
      this.boundaries = state.boundaries;
      this.selectedItems.clear();
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
      this._refreshThreatBadges();
    }

    redo() {
      if (this._redoStack.length === 0) return;
      this._undoStack.push({
        nodes: JSON.parse(JSON.stringify(this.nodes)),
        edges: JSON.parse(JSON.stringify(this.edges)),
        boundaries: JSON.parse(JSON.stringify(this.boundaries)),
      });
      const state = this._redoStack.pop();
      this.nodes = state.nodes;
      this.edges = state.edges;
      this.boundaries = state.boundaries;
      this.selectedItems.clear();
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
      this._refreshThreatBadges();
    }

    _addNode(type, x, y) {
      this._saveUndo();
      const defaults = NODE_DEFAULTS[type];
      const node = {
        id: uid('n'),
        type,
        label: defaults.label,
        x: this._snap(x - defaults.width / 2),
        y: this._snap(y - defaults.height / 2),
        width: defaults.width,
        height: defaults.height,
        scope: defaults.scope,
        description: '',
      };
      this.nodes.push(node);
      this.selectedItems.clear();
      this.selectedItems.add(node.id);
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
      this._updateProperties();
    }

    _deleteNode(id) {
      this._saveUndo();
      this.nodes = this.nodes.filter(n => n.id !== id);
      this.edges = this.edges.filter(e => e.sourceId !== id && e.targetId !== id);
      this.selectedItems.delete(id);
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
      this._refreshThreatBadges();
      this._updateProperties();
    }

    _duplicateNode(id) {
      const src = this._findNode(id);
      if (!src) return;
      this._saveUndo();
      const dup = { ...src, id: uid('n'), x: src.x + 30, y: src.y + 30 };
      this.nodes.push(dup);
      this.selectedItems.clear();
      this.selectedItems.add(dup.id);
      this._render();
      this._updateMermaidCode();
    }

    _editNodeLabel(id) {
      const node = this._findNode(id);
      if (!node) return;
      this._startInlineEdit(node, 'node');
    }

    _startInlineEdit(item, type) {
      if (this._inlineEditor) this._finishInlineEdit(false);
      const svg = this._svg;
      const fo = document.createElementNS(SVG_NS, 'foreignObject');
      let x, y, w, h;
      if (type === 'node') {
        x = item.x + 4; y = item.y + 8; w = item.width - 8; h = item.height - 16;
      } else if (type === 'boundary') {
        x = item.x + 6; y = item.y + 2; w = Math.min(item.width - 12, 200); h = 22;
      } else {
        // edge — place at midpoint
        const src = this._findNode(item.sourceId);
        const tgt = this._findNode(item.targetId);
        if (!src || !tgt) return;
        x = (src.x + src.width/2 + tgt.x + tgt.width/2) / 2 - 60;
        y = (src.y + src.height/2 + tgt.y + tgt.height/2) / 2 - 14;
        w = 120; h = 22;
      }
      fo.setAttribute('x', x); fo.setAttribute('y', y);
      fo.setAttribute('width', w); fo.setAttribute('height', h);
      const input = document.createElement('input');
      input.type = 'text';
      input.value = item.label || '';
      input.style.cssText = `width:100%;height:100%;background:#232323;color:#fff;border:1.5px solid #28D07D;border-radius:4px;padding:2px 6px;font-size:12px;font-family:system-ui;outline:none;box-sizing:border-box;`;
      fo.appendChild(input);
      this._layerOverlay.appendChild(fo);
      this._inlineEditor = { fo, input, item, type };
      requestAnimationFrame(() => { input.focus(); input.select(); });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); this._finishInlineEdit(true); }
        else if (e.key === 'Escape') { e.preventDefault(); this._finishInlineEdit(false); }
        e.stopPropagation();
      });
      input.addEventListener('blur', () => setTimeout(() => this._finishInlineEdit(true), 100));
    }

    _finishInlineEdit(save) {
      if (!this._inlineEditor) return;
      const { fo, input, item, type } = this._inlineEditor;
      this._inlineEditor = null;
      const val = input.value.trim();
      if (fo.parentNode) fo.parentNode.removeChild(fo);
      if (!save || !val) return;
      if (val === (item.label || '')) return;
      this._saveUndo();
      item.label = val;
      if (type === 'edge') item.protocol = val;
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
      if (type === 'node') this._refreshThreatBadges();
    }

    _addEdge(sourceId, targetId) {
      if (sourceId === targetId) return;
      if (this.edges.some(e => e.sourceId === sourceId && e.targetId === targetId)) return;
      this._saveUndo();
      this.edges.push({
        id: uid('e'), sourceId, targetId,
        label: '', protocol: '', dataType: '', bidirectional: false,
      });
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
    }

    _deleteEdge(id) {
      this._saveUndo();
      this.edges = this.edges.filter(e => e.id !== id);
      this.selectedItems.delete(id);
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
    }

    _editEdgeLabel(id) {
      const edge = this.edges.find(e => e.id === id);
      if (!edge) return;
      this._startInlineEdit(edge, 'edge');
    }

    _reverseEdge(id) {
      const edge = this.edges.find(e => e.id === id);
      if (!edge) return;
      this._saveUndo();
      [edge.sourceId, edge.targetId] = [edge.targetId, edge.sourceId];
      this._render();
      this._updateMermaidCode();
    }

    _addBoundary(x, y) {
      this._saveUndo();
      this.boundaries.push({
        id: uid('b'), label: 'Trust Boundary',
        x: this._snap(x), y: this._snap(y), width: 260, height: 200,
      });
      this._render();
      this._updateMermaidCode();
    }

    _editBoundaryLabel(id) {
      const b = this._findBoundary(id);
      if (!b) return;
      this._startInlineEdit(b, 'boundary');
    }

    deleteSelected() {
      if (this.selectedItems.size === 0) return;
      this._saveUndo();
      for (const id of this.selectedItems) {
        const ni = this.nodes.findIndex(n => n.id === id);
        if (ni >= 0) {
          this.edges = this.edges.filter(e => e.sourceId !== id && e.targetId !== id);
          this.nodes.splice(ni, 1);
          continue;
        }
        const ei = this.edges.findIndex(e => e.id === id);
        if (ei >= 0) { this.edges.splice(ei, 1); continue; }
        const bi = this.boundaries.findIndex(b => b.id === id);
        if (bi >= 0) this.boundaries.splice(bi, 1);
      }
      this.selectedItems.clear();
      this._render();
      this._updateMermaidCode();
      this._updateDescription();
      this._refreshThreatBadges();
      this._updateProperties();
    }

    _selectItem(id, add) {
      if (!add) this.selectedItems.clear();
      this.selectedItems.add(id);
      this._render();
      this._updateProperties();
    }

    _findNode(id) { return this.nodes.find(n => n.id === id); }
    _findBoundary(id) { return this.boundaries.find(b => b.id === id); }

    /* ═══════════════════════════════════
       Rendering
       ═══════════════════════════════════ */
    _render() {
      this._layerBoundaries.innerHTML = '';
      this._layerEdges.innerHTML = '';
      this._layerNodes.innerHTML = '';
      this._layerOverlay.innerHTML = '';

      this._emptyState.style.display = (this.nodes.length === 0) ? 'flex' : 'none';

      for (const b of this.boundaries) this._renderBoundary(b);
      for (const e of this.edges) this._renderEdge(e);
      for (const n of this.nodes) this._renderNode(n);

      // Re-add threat badges
      this._refreshThreatBadges();

      // Connection ports on nodes (visible on hover via CSS)
      for (const n of this.nodes) {
        this._renderConnectionPorts(n);
      }

      this._updateMinimap();
    }

    _renderConnectionPorts(node) {
      const ports = [
        { x: node.x + node.width/2, y: node.y, dir: 'top' },
        { x: node.x + node.width, y: node.y + node.height/2, dir: 'right' },
        { x: node.x + node.width/2, y: node.y + node.height, dir: 'bottom' },
        { x: node.x, y: node.y + node.height/2, dir: 'left' },
      ];
      const nodeG = this._layerNodes.querySelector(`[data-node-id="${node.id}"]`);
      if (!nodeG) return;
      for (const p of ports) {
        const c = document.createElementNS(SVG_NS, 'circle');
        c.setAttribute('cx', p.x); c.setAttribute('cy', p.y);
        c.setAttribute('r', '4');
        c.setAttribute('class', 'dfd-port');
        c.dataset.nodeId = node.id;
        c.dataset.portDir = p.dir;
        nodeG.appendChild(c);
      }
    }

    _renderNode(node) {
      const g = document.createElementNS(SVG_NS, 'g');
      const isSelected = this.selectedItems.has(node.id);
      const isHighlighted = this.highlightedNodeId === node.id;
      g.setAttribute('class', `dfd-node dfd-node-${node.type}${isSelected ? ' selected' : ''}${isHighlighted ? ' threat-highlight' : ''}`);
      g.dataset.nodeId = node.id;

      const { x, y, width, height } = node;

      if (node.type === 'data_store') {
        const body = document.createElementNS(SVG_NS, 'g');
        body.setAttribute('class', 'dfd-node-body');
        const rect = document.createElementNS(SVG_NS, 'rect');
        rect.setAttribute('x', x); rect.setAttribute('y', y);
        rect.setAttribute('width', width); rect.setAttribute('height', height);
        rect.setAttribute('fill', '#1e2f2a');
        rect.setAttribute('stroke', isSelected ? '#28D07D' : '#28D07D');
        rect.setAttribute('stroke-width', isSelected || isHighlighted ? '2.5' : '1.5');
        rect.setAttribute('rx', '4');
        const topLine = document.createElementNS(SVG_NS, 'line');
        topLine.setAttribute('x1', x); topLine.setAttribute('y1', y + 14);
        topLine.setAttribute('x2', x + width); topLine.setAttribute('y2', y + 14);
        topLine.setAttribute('stroke', '#28D07D'); topLine.setAttribute('stroke-width', '0.8'); topLine.setAttribute('opacity', '0.5');
        body.append(rect, topLine);
        g.appendChild(body);
      } else if (node.type === 'external_entity') {
        const body = document.createElementNS(SVG_NS, 'rect');
        body.setAttribute('class', 'dfd-node-body');
        body.setAttribute('x', x); body.setAttribute('y', y);
        body.setAttribute('width', width); body.setAttribute('height', height);
        body.setAttribute('fill', '#3a2f1e');
        body.setAttribute('stroke', isSelected ? '#28D07D' : '#c4943a');
        body.setAttribute('stroke-width', isSelected || isHighlighted ? '2.5' : '1.5');
        body.setAttribute('rx', '4');
        g.appendChild(body);
      } else {
        const body = document.createElementNS(SVG_NS, 'rect');
        body.setAttribute('class', 'dfd-node-body');
        body.setAttribute('x', x); body.setAttribute('y', y);
        body.setAttribute('width', width); body.setAttribute('height', height);
        body.setAttribute('fill', '#2d2d2d');
        body.setAttribute('stroke', isSelected ? '#28D07D' : '#3a3a3a');
        body.setAttribute('stroke-width', isSelected || isHighlighted ? '2.5' : '1.5');
        body.setAttribute('rx', '8');
        g.appendChild(body);
      }

      // Label
      const text = document.createElementNS(SVG_NS, 'text');
      text.setAttribute('class', 'dfd-node-label');
      text.setAttribute('x', x + width / 2);
      text.setAttribute('y', y + height / 2);
      const maxChars = Math.floor(width / 8);
      text.textContent = node.label.length > maxChars ? node.label.substring(0, maxChars - 1) + '…' : node.label;
      g.appendChild(text);

      // Type indicator
      const typeLabel = document.createElementNS(SVG_NS, 'text');
      typeLabel.setAttribute('x', x + width / 2);
      typeLabel.setAttribute('y', y + height - 6);
      typeLabel.setAttribute('class', 'dfd-node-label');
      typeLabel.setAttribute('font-size', '8');
      typeLabel.setAttribute('opacity', '0.4');
      const typeNames = { process: 'PROCESS', external_entity: 'EXTERNAL', data_store: 'DATA STORE' };
      typeLabel.textContent = typeNames[node.type] || '';
      g.appendChild(typeLabel);

      this._layerNodes.appendChild(g);
    }

    _renderEdge(edge) {
      const src = this._findNode(edge.sourceId);
      const tgt = this._findNode(edge.targetId);
      if (!src || !tgt) return;

      const g = document.createElementNS(SVG_NS, 'g');
      g.setAttribute('class', `dfd-edge${this.selectedItems.has(edge.id) ? ' selected' : ''}`);
      g.dataset.edgeId = edge.id;

      // Compute center points
      const sx = src.x + src.width / 2, sy = src.y + src.height / 2;
      const tx = tgt.x + tgt.width / 2, ty = tgt.y + tgt.height / 2;

      // Determine best ports (closest sides)
      const ports = this._bestPorts(src, tgt);
      const s = ports.source;
      const t = ports.target;

      const path = document.createElementNS(SVG_NS, 'path');
      path.setAttribute('class', 'dfd-edge-path');

      let d, midX, midY;
      if (this.edgeRouting === 'orthogonal') {
        // Manhattan routing with one bend
        const pts = this._orthogonalRoute(s, t, ports.sourceDir, ports.targetDir);
        d = 'M' + pts.map(p => `${p.x},${p.y}`).join(' L');
        // Midpoint for label
        const mp = pts[Math.floor(pts.length / 2)];
        midX = mp.x; midY = mp.y - 10;
      } else if (this.edgeRouting === 'curved') {
        // Cubic Bézier
        const dx = tx - sx, dy = ty - sy;
        const cx1 = s.x + dx * 0.35, cy1 = s.y;
        const cx2 = t.x - dx * 0.35, cy2 = t.y;
        d = `M${s.x},${s.y} C${cx1},${cy1} ${cx2},${cy2} ${t.x},${t.y}`;
        midX = (s.x + t.x) / 2; midY = (s.y + t.y) / 2 - 10;
      } else {
        d = `M${s.x},${s.y} L${t.x},${t.y}`;
        midX = (s.x + t.x) / 2; midY = (s.y + t.y) / 2 - 8;
      }
      path.setAttribute('d', d);
      g.appendChild(path);

      // Label with background pill
      if (edge.label) {
        const bg = document.createElementNS(SVG_NS, 'rect');
        const textLen = edge.label.length * 6.5 + 12;
        bg.setAttribute('x', midX - textLen / 2);
        bg.setAttribute('y', midY - 10);
        bg.setAttribute('width', textLen);
        bg.setAttribute('height', 16);
        bg.setAttribute('rx', 8);
        bg.setAttribute('fill', '#232323');
        bg.setAttribute('stroke', '#3a3a3a');
        bg.setAttribute('stroke-width', '0.5');
        g.appendChild(bg);

        const label = document.createElementNS(SVG_NS, 'text');
        label.setAttribute('class', 'dfd-edge-label');
        label.setAttribute('x', midX); label.setAttribute('y', midY);
        label.textContent = edge.label;
        g.appendChild(label);
      }

      this._layerEdges.appendChild(g);
    }

    _bestPorts(src, tgt) {
      const sc = { x: src.x + src.width/2, y: src.y + src.height/2 };
      const tc = { x: tgt.x + tgt.width/2, y: tgt.y + tgt.height/2 };
      const ports = [
        { dir: 'top', node: null, x: 0, y: 0 },
        { dir: 'right', node: null, x: 0, y: 0 },
        { dir: 'bottom', node: null, x: 0, y: 0 },
        { dir: 'left', node: null, x: 0, y: 0 },
      ];
      const getPort = (node, dir) => {
        switch(dir) {
          case 'top': return { x: node.x + node.width/2, y: node.y };
          case 'bottom': return { x: node.x + node.width/2, y: node.y + node.height };
          case 'left': return { x: node.x, y: node.y + node.height/2 };
          case 'right': return { x: node.x + node.width, y: node.y + node.height/2 };
        }
      };
      const dirs = ['top','right','bottom','left'];
      let bestDist = Infinity, bestSDir = 'right', bestTDir = 'left';
      for (const sd of dirs) {
        const sp = getPort(src, sd);
        for (const td of dirs) {
          const tp = getPort(tgt, td);
          const dist = Math.hypot(sp.x - tp.x, sp.y - tp.y);
          if (dist < bestDist) {
            bestDist = dist; bestSDir = sd; bestTDir = td;
          }
        }
      }
      return {
        source: getPort(src, bestSDir), target: getPort(tgt, bestTDir),
        sourceDir: bestSDir, targetDir: bestTDir,
      };
    }

    _orthogonalRoute(s, t, sDir, tDir) {
      const GAP = 20;
      const pts = [{ x: s.x, y: s.y }];
      // Extend out from source
      const sExt = this._extendPoint(s, sDir, GAP);
      pts.push(sExt);
      // Extend in from target
      const tExt = this._extendPoint(t, tDir, GAP);
      // Connect the two extension points with at most two bends
      if (sDir === 'left' || sDir === 'right') {
        if (tDir === 'left' || tDir === 'right') {
          const midX = (sExt.x + tExt.x) / 2;
          pts.push({ x: midX, y: sExt.y });
          pts.push({ x: midX, y: tExt.y });
        } else {
          pts.push({ x: tExt.x, y: sExt.y });
        }
      } else {
        if (tDir === 'top' || tDir === 'bottom') {
          const midY = (sExt.y + tExt.y) / 2;
          pts.push({ x: sExt.x, y: midY });
          pts.push({ x: tExt.x, y: midY });
        } else {
          pts.push({ x: sExt.x, y: tExt.y });
        }
      }
      pts.push(tExt);
      pts.push({ x: t.x, y: t.y });
      return pts;
    }

    _extendPoint(p, dir, dist) {
      switch(dir) {
        case 'top': return { x: p.x, y: p.y - dist };
        case 'bottom': return { x: p.x, y: p.y + dist };
        case 'left': return { x: p.x - dist, y: p.y };
        case 'right': return { x: p.x + dist, y: p.y };
        default: return { ...p };
      }
    }

    _cycleEdgeRouting() {
      const modes = ['straight', 'orthogonal', 'curved'];
      const idx = modes.indexOf(this.edgeRouting);
      this.edgeRouting = modes[(idx + 1) % modes.length];
      if (this._routeBtn) this._routeBtn.title = `Edge: ${this.edgeRouting}`;
      this._render();
    }

    _renderBoundary(b) {
      const g = document.createElementNS(SVG_NS, 'g');
      g.setAttribute('class', `dfd-boundary${this.selectedItems.has(b.id) ? ' selected' : ''}`);
      g.dataset.boundaryId = b.id;

      const rect = document.createElementNS(SVG_NS, 'rect');
      rect.setAttribute('x', b.x); rect.setAttribute('y', b.y);
      rect.setAttribute('width', b.width); rect.setAttribute('height', b.height);
      g.appendChild(rect);

      const label = document.createElementNS(SVG_NS, 'text');
      label.setAttribute('class', 'dfd-boundary-label');
      label.setAttribute('x', b.x + 10); label.setAttribute('y', b.y + 16);
      label.textContent = b.label;
      g.appendChild(label);

      this._layerBoundaries.appendChild(g);
    }

    _clipToRect(fromX, fromY, toX, toY, node) {
      const { x, y, width, height } = node;
      const cx = x + width / 2, cy = y + height / 2;
      const dx = toX - fromX, dy = toY - fromY;
      if (dx === 0 && dy === 0) return { x: cx, y: cy };

      const scaleX = (width / 2) / Math.abs(dx || 1);
      const scaleY = (height / 2) / Math.abs(dy || 1);
      const scale = Math.min(scaleX, scaleY);

      return { x: cx + dx * scale, y: cy + dy * scale };
    }

    /* ═══════════════════════════════════
       Threat Badge Rendering on Nodes
       ═══════════════════════════════════ */
    _refreshThreatBadges() {
      if (!this.threats || this.threats.length === 0) return;

      const threatsByComp = this._groupThreatsByComponent();

      for (const node of this.nodes) {
        const nodeThreats = threatsByComp.get(node.label) || [];
        if (nodeThreats.length === 0) continue;

        const nodeEl = this._layerNodes.querySelector(`[data-node-id="${node.id}"]`);
        if (!nodeEl) continue;

        const badge = document.createElementNS(SVG_NS, 'g');
        badge.setAttribute('class', 'dfd-threat-badge');

        const critical = nodeThreats.filter(t => (t.priority || '').toLowerCase() === 'critical' || t.dread_total >= 45).length;
        const high = nodeThreats.filter(t => (t.priority || '').toLowerCase() === 'high' || (t.dread_total >= 35 && t.dread_total < 45)).length;
        const color = critical > 0 ? '#e05252' : high > 0 ? '#e89b3a' : '#d4b64c';

        const bx = node.x + node.width - 8;
        const by = node.y - 8;

        const bg = document.createElementNS(SVG_NS, 'rect');
        bg.setAttribute('class', 'dfd-threat-badge-bg');
        bg.setAttribute('x', bx - 10); bg.setAttribute('y', by - 10);
        bg.setAttribute('width', '22'); bg.setAttribute('height', '18');
        bg.setAttribute('fill', color);
        badge.appendChild(bg);

        const text = document.createElementNS(SVG_NS, 'text');
        text.setAttribute('class', 'dfd-threat-badge-text');
        text.setAttribute('x', bx + 1); text.setAttribute('y', by);
        text.textContent = nodeThreats.length;
        badge.appendChild(text);

        const title = document.createElementNS(SVG_NS, 'title');
        title.textContent = nodeThreats.map(t => `[${t.stride_category || '?'}] ${(t.description || '').substring(0, 80)}`).join('\n');
        badge.appendChild(title);

        // Click badge → expand threats for this component
        badge.style.cursor = 'pointer';
        badge.addEventListener('click', (e) => {
          e.stopPropagation();
          this._highlightComponentThreats(node.id);
        });

        nodeEl.appendChild(badge);
      }
    }

    _groupThreatsByComponent() {
      const map = new Map();
      for (const t of this.threats) {
        const comp = t.component || '';
        if (!map.has(comp)) map.set(comp, []);
        map.get(comp).push(t);
      }
      return map;
    }

    /* ═══════════════════════════════════
       Threat Sidebar
       ═══════════════════════════════════ */
    _renderThreatList() {
      const container = this._threatListEl;
      container.innerHTML = '';

      if (!this.threats || this.threats.length === 0) {
        container.innerHTML = '<div class="dfd-props-empty">No threats detected</div>';
        return;
      }

      // Update count badge
      const countEl = this._threatSidebar.querySelector('#dfdThreatCount');
      if (countEl) countEl.textContent = this.threats.length;

      // Filter & search
      let filtered = this.threats;
      if (this._activeFilter !== 'all') {
        filtered = filtered.filter(t => (t.priority || '').toLowerCase() === this._activeFilter.toLowerCase());
      }
      if (this._searchQuery) {
        filtered = filtered.filter(t =>
          (t.description || '').toLowerCase().includes(this._searchQuery) ||
          (t.component || '').toLowerCase().includes(this._searchQuery) ||
          (t.stride_category || '').toLowerCase().includes(this._searchQuery) ||
          (t.mitigation || '').toLowerCase().includes(this._searchQuery)
        );
      }

      // Group by component
      const groups = new Map();
      for (const t of filtered) {
        const comp = t.component || 'General';
        if (!groups.has(comp)) groups.set(comp, []);
        groups.get(comp).push(t);
      }

      // Sort groups by highest severity
      const prioOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const sortedGroups = [...groups.entries()].sort((a, b) => {
        const maxA = Math.min(...a[1].map(t => prioOrder[(t.priority || 'medium').toLowerCase()] ?? 2));
        const maxB = Math.min(...b[1].map(t => prioOrder[(t.priority || 'medium').toLowerCase()] ?? 2));
        return maxA - maxB;
      });

      for (const [comp, threats] of sortedGroups) {
        const group = document.createElement('div');
        group.className = 'dfd-threat-group';
        group.dataset.component = comp;

        // Find node type for icon
        const node = this.nodes.find(n => n.label === comp);
        const nodeType = node?.type || 'process';

        // Determine highest severity
        const severities = threats.map(t => (t.priority || 'Medium').toLowerCase());
        const maxSev = severities.includes('critical') ? 'critical' : severities.includes('high') ? 'high' : severities.includes('medium') ? 'medium' : 'low';

        // Header
        const header = document.createElement('div');
        header.className = 'dfd-threat-group-header';
        header.innerHTML = `
          <div class="dfd-threat-group-icon ${nodeType}">
            ${nodeType === 'data_store' ? '◆' : nodeType === 'external_entity' ? '◇' : '□'}
          </div>
          <div class="dfd-threat-group-name">${this._esc(comp)}</div>
          <span class="dfd-threat-group-count ${maxSev}">${threats.length}</span>
          <span class="dfd-threat-group-chevron">▶</span>
        `;
        header.addEventListener('click', () => {
          group.classList.toggle('expanded');
          // Highlight node on diagram
          if (node) this._highlightNode(node.id);
        });
        group.appendChild(header);

        // Body — threat cards
        const body = document.createElement('div');
        body.className = 'dfd-threat-group-body';

        for (const t of threats) {
          const card = document.createElement('div');
          card.className = 'dfd-threat-card';
          card.dataset.threatId = t.id;

          const prio = (t.priority || 'Medium');
          card.innerHTML = `
            <div class="dfd-threat-card-header">
              <div class="dfd-threat-severity ${prio}"></div>
              <div class="dfd-threat-card-title">${this._esc((t.description || '').substring(0, 120))}</div>
            </div>
            <div class="dfd-threat-card-meta">
              ${t.stride_category ? `<span class="dfd-threat-tag stride">${this._esc(t.stride_category)}</span>` : ''}
              <span class="dfd-threat-tag dread">DREAD: ${t.dread_total || 0}</span>
              <span class="dfd-threat-tag priority">${this._esc(prio)}</span>
            </div>
            <div class="dfd-threat-card-mitigation">
              <strong>Control:</strong> ${this._esc((t.mitigation || 'No mitigation specified').substring(0, 200))}
            </div>
          `;

          card.addEventListener('click', (e) => {
            e.stopPropagation();
            // Toggle selection
            const wasSelected = card.classList.contains('selected');
            container.querySelectorAll('.dfd-threat-card').forEach(c => c.classList.remove('selected'));
            if (!wasSelected) {
              card.classList.add('selected');
              this.selectedThreatId = t.id;
              // Highlight the component node
              if (node) this._highlightNode(node.id);
            } else {
              this.selectedThreatId = null;
              this._clearHighlights();
            }
          });

          body.appendChild(card);
        }

        group.appendChild(body);
        container.appendChild(group);
      }
    }

    _setThreatFilter(filter) {
      this._activeFilter = filter;
      this._threatSidebar.querySelectorAll('.dfd-threat-filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
      });
      this._renderThreatList();
    }

    _highlightNode(nodeId) {
      this.highlightedNodeId = nodeId;
      this._render();

      // Pan into view
      const node = this._findNode(nodeId);
      if (node) {
        const rect = this._svg.getBoundingClientRect();
        const targetX = rect.width / 2 - (node.x + node.width / 2) * this.zoom;
        const targetY = rect.height / 2 - (node.y + node.height / 2) * this.zoom;
        // Smooth pan
        const startX = this.panX, startY = this.panY;
        const steps = 20;
        let step = 0;
        const animate = () => {
          step++;
          const t = step / steps;
          const ease = t * (2 - t); // ease-out
          this.panX = startX + (targetX - startX) * ease;
          this.panY = startY + (targetY - startY) * ease;
          this._applyTransform();
          if (step < steps) requestAnimationFrame(animate);
        };
        animate();
      }
    }

    _highlightComponentThreats(nodeId) {
      const node = this._findNode(nodeId);
      if (!node) return;

      this.highlightedNodeId = nodeId;
      this._render();

      // Open the threat group for this component
      this._threatListEl.querySelectorAll('.dfd-threat-group').forEach(g => {
        const isTarget = g.dataset.component === node.label;
        g.classList.toggle('expanded', isTarget);
        g.classList.toggle('highlighted', isTarget);
      });

      // Scroll to it
      const targetGroup = this._threatListEl.querySelector(`[data-component="${CSS.escape(node.label)}"]`);
      if (targetGroup) {
        targetGroup.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }

    _clearHighlights() {
      this.highlightedNodeId = null;
      this.selectedThreatId = null;
      this._threatListEl.querySelectorAll('.dfd-threat-group').forEach(g => {
        g.classList.remove('highlighted');
      });
      this._threatListEl.querySelectorAll('.dfd-threat-card').forEach(c => {
        c.classList.remove('selected');
      });
    }

    _toggleThreatSidebar() {
      this._threatSidebarCollapsed = !this._threatSidebarCollapsed;
      this._threatSidebar.classList.toggle('collapsed', this._threatSidebarCollapsed);
    }

    /* ═══════════════════════════════════
       Properties Panel
       ═══════════════════════════════════ */
    _updateProperties() {
      if (this.selectedItems.size === 0) {
        this._propsBody.innerHTML = '<div class="dfd-props-empty">Select a component to edit its properties</div>';
        if (this._propertiesCollapsed) {
          this._propertiesCollapsed = false;
          this._properties.classList.remove('collapsed');
        }
        return;
      }
      if (this._propertiesCollapsed) {
        this._propertiesCollapsed = false;
        this._properties.classList.remove('collapsed');
      }

      const id = [...this.selectedItems][0];
      const node = this._findNode(id);
      const edge = this.edges.find(e => e.id === id);
      const boundary = this._findBoundary(id);

      this._propsBody.innerHTML = '';

      if (node) {
        this._propsBody.innerHTML = `
          <div class="dfd-props-field">
            <div class="dfd-props-label">Name</div>
            <input class="dfd-props-input" id="propLabel" value="${this._esc(node.label)}" />
          </div>
          <div class="dfd-props-field">
            <div class="dfd-props-label">Type</div>
            <select class="dfd-props-select" id="propType">
              <option value="process" ${node.type === 'process' ? 'selected' : ''}>Process</option>
              <option value="external_entity" ${node.type === 'external_entity' ? 'selected' : ''}>External Entity</option>
              <option value="data_store" ${node.type === 'data_store' ? 'selected' : ''}>Data Store</option>
            </select>
          </div>
          <div class="dfd-props-field">
            <div class="dfd-props-label">Scope</div>
            <select class="dfd-props-select" id="propScope">
              <option value="internal" ${node.scope === 'internal' ? 'selected' : ''}>Internal</option>
              <option value="dmz" ${node.scope === 'dmz' ? 'selected' : ''}>DMZ</option>
              <option value="public" ${node.scope === 'public' ? 'selected' : ''}>Public</option>
              <option value="cloud" ${node.scope === 'cloud' ? 'selected' : ''}>Cloud</option>
              <option value="external" ${node.scope === 'external' ? 'selected' : ''}>External</option>
            </select>
          </div>
          <div class="dfd-props-field">
            <div class="dfd-props-label">Description</div>
            <textarea class="dfd-props-textarea" id="propDesc">${this._esc(node.description || '')}</textarea>
          </div>
        `;
        this._propsBody.querySelector('#propLabel').addEventListener('change', (e) => {
          this._saveUndo(); node.label = e.target.value; this._render(); this._updateMermaidCode(); this._refreshThreatBadges();
        });
        this._propsBody.querySelector('#propType').addEventListener('change', (e) => {
          this._saveUndo(); node.type = e.target.value; this._render(); this._updateMermaidCode();
        });
        this._propsBody.querySelector('#propScope').addEventListener('change', (e) => {
          this._saveUndo(); node.scope = e.target.value;
        });
        this._propsBody.querySelector('#propDesc').addEventListener('change', (e) => {
          node.description = e.target.value;
        });

        // Show threats for this node
        const nodeThreats = (this._groupThreatsByComponent().get(node.label) || []);
        if (nodeThreats.length > 0) {
          const threatSection = document.createElement('div');
          threatSection.className = 'dfd-props-field';
          threatSection.innerHTML = `
            <div class="dfd-props-label">Threats (${nodeThreats.length})</div>
            ${nodeThreats.map(t => `
              <div style="font-size:0.72rem;padding:4px 0;border-bottom:1px solid var(--border);color:var(--text2)">
                <span style="color:${(t.priority || '').toLowerCase() === 'critical' ? '#e05252' : (t.priority || '').toLowerCase() === 'high' ? '#e89b3a' : '#d4b64c'}">●</span>
                ${this._esc((t.description || '').substring(0, 80))}
                <span style="opacity:0.5;font-size:0.65rem;margin-left:4px">${t.stride_category || ''}</span>
              </div>
            `).join('')}
          `;
          this._propsBody.appendChild(threatSection);
        }
      } else if (edge) {
        const src = this._findNode(edge.sourceId);
        const tgt = this._findNode(edge.targetId);
        this._propsBody.innerHTML = `
          <div class="dfd-props-field">
            <div class="dfd-props-label">Flow</div>
            <div style="font-size:0.76rem;color:var(--text2)">${this._esc(src?.label || '?')} → ${this._esc(tgt?.label || '?')}</div>
          </div>
          <div class="dfd-props-field">
            <div class="dfd-props-label">Label / Protocol</div>
            <input class="dfd-props-input" id="propEdgeLabel" value="${this._esc(edge.label)}" />
          </div>
          <div class="dfd-props-field">
            <div class="dfd-props-label">Data Type</div>
            <input class="dfd-props-input" id="propEdgeData" value="${this._esc(edge.dataType || '')}" />
          </div>
        `;
        this._propsBody.querySelector('#propEdgeLabel').addEventListener('change', (e) => {
          this._saveUndo(); edge.label = e.target.value; edge.protocol = e.target.value; this._render(); this._updateMermaidCode();
        });
        this._propsBody.querySelector('#propEdgeData').addEventListener('change', (e) => {
          edge.dataType = e.target.value;
        });
      } else if (boundary) {
        this._propsBody.innerHTML = `
          <div class="dfd-props-field">
            <div class="dfd-props-label">Boundary Name</div>
            <input class="dfd-props-input" id="propBLabel" value="${this._esc(boundary.label)}" />
          </div>
        `;
        this._propsBody.querySelector('#propBLabel').addEventListener('change', (e) => {
          this._saveUndo(); boundary.label = e.target.value; this._render(); this._updateMermaidCode();
        });
      }
    }

    /* ═══════════════════════════════════
       Transform / Zoom
       ═══════════════════════════════════ */
    _applyTransform() {
      this._transformGroup.setAttribute('transform', `translate(${this.panX},${this.panY}) scale(${this.zoom})`);
      this._updateMinimap();
    }

    _setZoom(z) {
      this.zoom = Math.max(0.2, Math.min(3, z));
      this._applyTransform();
      this._updateZoomDisplay();
    }

    _updateZoomDisplay() {
      const el = this._canvasContainer.querySelector('#dfdZoomLevel');
      if (el) el.textContent = Math.round(this.zoom * 100) + '%';
    }

    fitToView() {
      if (this.nodes.length === 0) return;
      const allItems = [...this.nodes, ...this.boundaries];
      const minX = Math.min(...allItems.map(n => n.x));
      const minY = Math.min(...allItems.map(n => n.y));
      const maxX = Math.max(...allItems.map(n => n.x + (n.width || 140)));
      const maxY = Math.max(...allItems.map(n => n.y + (n.height || 60)));
      const pad = 60;
      const rect = this._svg.getBoundingClientRect();
      const scaleX = (rect.width - pad * 2) / (maxX - minX + pad);
      const scaleY = (rect.height - pad * 2) / (maxY - minY + pad);
      this.zoom = Math.max(0.2, Math.min(1.5, Math.min(scaleX, scaleY)));
      this.panX = (rect.width - (maxX + minX) * this.zoom) / 2;
      this.panY = (rect.height - (maxY + minY) * this.zoom) / 2;
      this._applyTransform();
      this._updateZoomDisplay();
    }

    /* ═══════════════════════════════════
       Context Menu
       ═══════════════════════════════════ */
    _showContextMenu(x, y, items) {
      this._hideContextMenu();
      const menu = document.createElement('div');
      menu.className = 'dfd-context-menu';
      menu.style.left = x + 'px';
      menu.style.top = y + 'px';

      for (const item of items) {
        if (item.separator) {
          const sep = document.createElement('div');
          sep.className = 'dfd-context-sep';
          menu.appendChild(sep);
          continue;
        }
        const el = document.createElement('div');
        el.className = 'dfd-context-item' + (item.danger ? ' danger' : '');
        el.innerHTML = `<span>${item.icon}</span> ${item.label}`;
        el.addEventListener('click', () => { this._hideContextMenu(); item.action(); });
        menu.appendChild(el);
      }

      document.body.appendChild(menu);
      this._contextMenu = menu;
    }

    _hideContextMenu() {
      if (this._contextMenu) { this._contextMenu.remove(); this._contextMenu = null; }
    }

    /* ═══════════════════════════════════
       Bottom Panel
       ═══════════════════════════════════ */
    _switchBottomTab(tab) {
      this._bottomPanel.querySelectorAll('.dfd-bottom-tab').forEach(t => t.classList.toggle('active', t.dataset.btab === tab));
      this._mermaidEditor.style.display = tab === 'mermaid' ? '' : 'none';
      this._descriptionEditor.style.display = tab === 'description' ? '' : 'none';
    }

    _toggleBottomPanel() {
      this._bottomPanel.classList.toggle('collapsed');
    }

    /* ═══════════════════════════════════
       Mermaid Code Generation (DFD → Mermaid)
       ═══════════════════════════════════ */
    _updateMermaidCode() {
      this._mermaidEditor.value = this.toMermaid();
    }

    toMermaid() {
      if (this.nodes.length === 0) return '';
      const lines = ['flowchart TD'];
      const idMap = new Map();

      for (const n of this.nodes) {
        let safeId = n.label.replace(/[^a-zA-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || `node${this.nodes.indexOf(n)}`;
        let finalId = safeId;
        let counter = 2;
        while ([...idMap.values()].includes(finalId)) { finalId = safeId + counter++; }
        idMap.set(n.id, finalId);
      }

      // Nodes in boundaries
      const inBoundary = new Map();
      for (const b of this.boundaries) {
        for (const n of this.nodes) {
          if (n.x >= b.x && n.x + n.width <= b.x + b.width && n.y >= b.y && n.y + n.height <= b.y + b.height) {
            inBoundary.set(n.id, b.id);
          }
        }
      }

      const bNodes = new Map();
      const unbounded = [];
      for (const n of this.nodes) {
        const bId = inBoundary.get(n.id);
        if (bId) { if (!bNodes.has(bId)) bNodes.set(bId, []); bNodes.get(bId).push(n); }
        else unbounded.push(n);
      }

      for (const b of this.boundaries) {
        const nodes = bNodes.get(b.id) || [];
        lines.push(`  subgraph ${this._mermaidSafeId(b.label)}["${b.label}"]`);
        for (const n of nodes) lines.push(`    ${this._mermaidNodeStr(n, idMap)}`);
        lines.push('  end');
      }
      for (const n of unbounded) lines.push(`  ${this._mermaidNodeStr(n, idMap)}`);
      for (const e of this.edges) {
        const s = idMap.get(e.sourceId), t = idMap.get(e.targetId);
        if (!s || !t) continue;
        lines.push(e.label ? `  ${s} -->|${e.label}| ${t}` : `  ${s} --> ${t}`);
      }
      return lines.join('\n');
    }

    _mermaidNodeStr(node, idMap) {
      const id = idMap.get(node.id);
      switch (node.type) {
        case 'data_store': return `${id}[(${node.label})]`;
        case 'external_entity': return `${id}([${node.label}])`;
        default: return `${id}[${node.label}]`;
      }
    }

    _mermaidSafeId(str) {
      return str.replace(/[^a-zA-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'zone';
    }

    /* ═══════════════════════════════════
       Architecture Description
       ═══════════════════════════════════ */
    _updateDescription() {
      this._descriptionEditor.value = this.toDescription();
    }

    toDescription() {
      if (this.nodes.length === 0) return '';
      const lines = [];
      const processes = this.nodes.filter(n => n.type === 'process');
      const externals = this.nodes.filter(n => n.type === 'external_entity');
      const stores = this.nodes.filter(n => n.type === 'data_store');

      lines.push('## System Architecture\n');
      if (externals.length > 0) {
        lines.push('### External Entities');
        externals.forEach(n => lines.push(`- **${n.label}** (${n.scope})${n.description ? ': ' + n.description : ''}`));
        lines.push('');
      }
      if (processes.length > 0) {
        lines.push('### Processes');
        processes.forEach(n => lines.push(`- **${n.label}** (${n.scope})${n.description ? ': ' + n.description : ''}`));
        lines.push('');
      }
      if (stores.length > 0) {
        lines.push('### Data Stores');
        stores.forEach(n => lines.push(`- **${n.label}** (${n.scope})${n.description ? ': ' + n.description : ''}`));
        lines.push('');
      }
      if (this.edges.length > 0) {
        lines.push('### Data Flows');
        this.edges.forEach(e => {
          const s = this._findNode(e.sourceId), t = this._findNode(e.targetId);
          if (s && t) lines.push(`- **${s.label}** → **${t.label}**${e.label ? ' via ' + e.label : ''}`);
        });
        lines.push('');
      }
      if (this.boundaries.length > 0) {
        lines.push('### Trust Boundaries');
        this.boundaries.forEach(b => {
          const inside = this.nodes.filter(n => n.x >= b.x && n.x + n.width <= b.x + b.width && n.y >= b.y && n.y + n.height <= b.y + b.height);
          lines.push(`- **${b.label}**: ${inside.length > 0 ? inside.map(n => n.label).join(', ') : '(empty)'}`);
        });
      }
      return lines.join('\n');
    }

    /* ═══════════════════════════════════
       Mermaid → DFD (Bidirectional)
       ═══════════════════════════════════ */
    _parseMermaidInput() {
      const code = this._mermaidEditor.value.trim();
      if (!code) return;
      try {
        this.fromMermaid(code);
        this._showToast('Diagram updated from Mermaid code');
      } catch (err) { console.warn('Parse error:', err); }
    }

    fromMermaid(code) {
      const lines = code.split('\n');
      const newNodes = [], newEdges = [], newBoundaries = [];
      const nodeMap = new Map();
      let currentSub = null, yOff = 100, xOff = 100, col = 0;

      const nodePats = [
        { regex: /(\w+)\[\((.+?)\)\]/, type: 'data_store' },
        { regex: /(\w+)\(\[(.+?)\]\)/, type: 'external_entity' },
        { regex: /(\w+)\(\((.+?)\)\)/, type: 'process' },
        { regex: /(\w+)\{(.+?)\}/, type: 'process' },
        { regex: /(\w+)\[(.+?)\]/, type: 'process' },
        { regex: /(\w+)\((.+?)\)/, type: 'process' },
      ];
      const edgePats = [
        /(\w+)\s*-\.->(?:\|(.+?)\|)?\s*(\w+)/,
        /(\w+)\s*==>(?:\|(.+?)\|)?\s*(\w+)/,
        /(\w+)\s*-->(?:\|(.+?)\|)?\s*(\w+)/,
        /(\w+)\s*---\s*(\w+)/,
      ];

      for (const line of lines) {
        const s = line.trim();
        if (!s || s.startsWith('%%') || /^(flowchart|graph)\s/i.test(s)) continue;

        // Subgraph
        let sg = s.match(/^subgraph\s+(\w+)\s*\["?(.+?)"?\]/);
        if (!sg) { sg = s.match(/^subgraph\s+(.+)/); if (sg) sg = [null, sg[1].replace(/"/g, '').replace(/\W+/g, '_'), sg[1].replace(/"/g, '')]; }
        if (sg) {
          currentSub = { id: uid('b'), label: sg[2] || sg[1], x: xOff + col * 280, y: yOff, width: 250, height: 200 };
          newBoundaries.push(currentSub);
          continue;
        }
        if (s === 'end' && currentSub) { currentSub = null; col++; continue; }

        for (const pat of nodePats) {
          for (const m of [...s.matchAll(new RegExp(pat.regex, 'g'))]) {
            const mId = m[1], label = m[2];
            if (!nodeMap.has(mId)) {
              const def = NODE_DEFAULTS[pat.type] || NODE_DEFAULTS.process;
              const n = {
                id: uid('n'), type: pat.type, label,
                x: currentSub ? currentSub.x + 20 + (nodeMap.size % 2) * 120 : xOff + (nodeMap.size % 4) * 180,
                y: currentSub ? currentSub.y + 30 + Math.floor(nodeMap.size % 3) * 80 : yOff + Math.floor(nodeMap.size / 4) * 100,
                width: def.width, height: def.height,
                scope: pat.type === 'external_entity' ? 'external' : 'internal',
                description: '',
              };
              newNodes.push(n);
              nodeMap.set(mId, n);
            }
          }
        }

        const clean = s.replace(/\[\(.*?\)\]/g, '').replace(/\(\[.*?\]\)/g, '').replace(/\(\(.*?\)\)/g, '')
          .replace(/\{.*?\}/g, '').replace(/\[.*?\]/g, '').replace(/\(.*?\)/g, '');
        for (const ep of edgePats) {
          for (const m of [...clean.matchAll(new RegExp(ep, 'g'))]) {
            const srcId = m[1], label = m.length >= 4 ? (m[2] || '') : '', tgtId = m.length >= 4 ? m[3] : m[2];
            const srcN = nodeMap.get(srcId), tgtN = nodeMap.get(tgtId);
            if (srcN && tgtN) {
              newEdges.push({ id: uid('e'), sourceId: srcN.id, targetId: tgtN.id, label, protocol: label, dataType: '', bidirectional: false });
            }
          }
        }
      }

      if (newNodes.length > 0) {
        this._saveUndo();
        this.nodes = newNodes;
        this.edges = newEdges;
        this.boundaries = newBoundaries;
        this.selectedItems.clear();
        this._autoLayout();
        this._render();
        this._updateDescription();
        this._renderThreatList();
        this.fitToView();
      }
    }

    /* ═══════════════════════════════════
       Auto Layout
       ═══════════════════════════════════ */
    _autoLayout() {
      const padding = 40, colWidth = 180, rowHeight = 100;
      const externals = this.nodes.filter(n => n.type === 'external_entity');
      const processes = this.nodes.filter(n => n.type === 'process');
      const stores = this.nodes.filter(n => n.type === 'data_store');
      let y = 60;

      externals.forEach((n, i) => { n.x = 100 + i * colWidth; n.y = y; });
      y += externals.length > 0 ? rowHeight + padding : 0;
      processes.forEach((n, i) => { n.x = 100 + i * colWidth; n.y = y; });
      y += processes.length > 0 ? rowHeight + padding : 0;
      stores.forEach((n, i) => { n.x = 100 + i * colWidth; n.y = y; });

      this._fitBoundaries();
    }

    _fitBoundaries() {
      for (const b of this.boundaries) {
        const inside = this.nodes.filter(n => n.x >= b.x - 20 && n.x + n.width <= b.x + b.width + 20 && n.y >= b.y - 20 && n.y + n.height <= b.y + b.height + 20);
        if (inside.length > 0) {
          b.x = Math.min(...inside.map(n => n.x)) - 20;
          b.y = Math.min(...inside.map(n => n.y)) - 30;
          b.width = Math.max(...inside.map(n => n.x + n.width)) + 20 - b.x;
          b.height = Math.max(...inside.map(n => n.y + n.height)) + 20 - b.y;
        }
      }
    }

    /* ── Force-Directed Layout (Fruchterman-Reingold) ── */
    _forceLayout() {
      if (this.nodes.length === 0) return;
      this._saveUndo();

      const nodes = this.nodes;
      const edges = this.edges;
      const N = nodes.length;
      const area = Math.max(800, N * 200) * Math.max(600, N * 150);
      const k = Math.sqrt(area / N); // ideal spring length
      const iterations = 80;
      const cooling = 0.95;
      let temp = k * 1.5;

      // Init velocities
      const vx = new Float64Array(N);
      const vy = new Float64Array(N);

      // Build adjacency (index-based)
      const idxMap = new Map();
      nodes.forEach((n, i) => idxMap.set(n.id, i));

      for (let iter = 0; iter < iterations; iter++) {
        // Reset displacements
        vx.fill(0); vy.fill(0);

        // Repulsive forces (all pairs)
        for (let i = 0; i < N; i++) {
          for (let j = i + 1; j < N; j++) {
            let dx = nodes[i].x - nodes[j].x;
            let dy = nodes[i].y - nodes[j].y;
            const dist = Math.max(Math.sqrt(dx*dx + dy*dy), 1);
            const force = (k * k) / dist;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            vx[i] += fx; vy[i] += fy;
            vx[j] -= fx; vy[j] -= fy;
          }
        }

        // Attractive forces (edges)
        for (const e of edges) {
          const si = idxMap.get(e.sourceId);
          const ti = idxMap.get(e.targetId);
          if (si == null || ti == null) continue;
          let dx = nodes[si].x - nodes[ti].x;
          let dy = nodes[si].y - nodes[ti].y;
          const dist = Math.max(Math.sqrt(dx*dx + dy*dy), 1);
          const force = (dist * dist) / k;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          vx[si] -= fx; vy[si] -= fy;
          vx[ti] += fx; vy[ti] += fy;
        }

        // Gravity toward center
        const cx = nodes.reduce((s, n) => s + n.x, 0) / N;
        const cy = nodes.reduce((s, n) => s + n.y, 0) / N;
        for (let i = 0; i < N; i++) {
          vx[i] -= (nodes[i].x - cx) * 0.01;
          vy[i] -= (nodes[i].y - cy) * 0.01;
        }

        // Apply with temperature limiting
        for (let i = 0; i < N; i++) {
          const disp = Math.sqrt(vx[i]*vx[i] + vy[i]*vy[i]);
          if (disp > 0) {
            const scale = Math.min(disp, temp) / disp;
            nodes[i].x += vx[i] * scale;
            nodes[i].y += vy[i] * scale;
          }
          // Snap
          if (this.snapToGrid) {
            nodes[i].x = this._snap(nodes[i].x);
            nodes[i].y = this._snap(nodes[i].y);
          }
        }

        temp *= cooling;
      }

      // Normalize: shift so min is at (80, 80)
      const minX = Math.min(...nodes.map(n => n.x));
      const minY = Math.min(...nodes.map(n => n.y));
      nodes.forEach(n => { n.x -= minX - 80; n.y -= minY - 80; });

      this._fitBoundaries();
      this._render();
      this.fitToView();
      this._updateMermaidCode();
    }

    /* ── SVG / PNG Export ── */
    exportSVG() {
      const svgClone = this._svg.cloneNode(true);
      // Inline essential styles
      const styleEl = document.createElementNS(SVG_NS, 'style');
      styleEl.textContent = `
        .dfd-edge-path { fill: none; stroke: #6a6a6a; stroke-width: 1.5; marker-end: url(#arrowhead); }
        .dfd-edge-label { fill: #a0a0a0; font-size: 10px; text-anchor: middle; font-family: system-ui; }
        .dfd-node-label { fill: #ffffff; font-size: 12px; text-anchor: middle; font-family: system-ui; }
        .dfd-boundary rect { fill: rgba(232,155,58,0.06); stroke: #e89b3a; stroke-dasharray: 6 3; stroke-width: 1.5; rx: 8; }
        .dfd-boundary-label { fill: #e89b3a; font-size: 11px; font-family: system-ui; }
      `;
      svgClone.insertBefore(styleEl, svgClone.firstChild);
      // Set viewBox to content bounds
      const bbox = this._getContentBBox();
      svgClone.setAttribute('viewBox', `${bbox.x - 20} ${bbox.y - 20} ${bbox.w + 40} ${bbox.h + 40}`);
      svgClone.setAttribute('width', bbox.w + 40);
      svgClone.setAttribute('height', bbox.h + 40);
      svgClone.setAttribute('xmlns', SVG_NS);
      const blob = new Blob([new XMLSerializer().serializeToString(svgClone)], { type: 'image/svg+xml' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'dfd-diagram.svg';
      a.click();
      URL.revokeObjectURL(a.href);
    }

    exportPNG() {
      const bbox = this._getContentBBox();
      const W = bbox.w + 40, H = bbox.h + 40;
      const svgClone = this._svg.cloneNode(true);
      const styleEl = document.createElementNS(SVG_NS, 'style');
      styleEl.textContent = `
        .dfd-edge-path { fill: none; stroke: #6a6a6a; stroke-width: 1.5; marker-end: url(#arrowhead); }
        .dfd-edge-label { fill: #a0a0a0; font-size: 10px; text-anchor: middle; font-family: system-ui; }
        .dfd-node-label { fill: #ffffff; font-size: 12px; text-anchor: middle; font-family: system-ui; }
        .dfd-boundary rect { fill: rgba(232,155,58,0.06); stroke: #e89b3a; stroke-dasharray: 6 3; stroke-width: 1.5; rx: 8; }
        .dfd-boundary-label { fill: #e89b3a; font-size: 11px; font-family: system-ui; }
      `;
      svgClone.insertBefore(styleEl, svgClone.firstChild);
      svgClone.setAttribute('viewBox', `${bbox.x - 20} ${bbox.y - 20} ${W} ${H}`);
      svgClone.setAttribute('width', W * 2);
      svgClone.setAttribute('height', H * 2);
      svgClone.setAttribute('xmlns', SVG_NS);
      const svgData = new XMLSerializer().serializeToString(svgClone);
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = W * 2; canvas.height = H * 2;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#1b1b1b';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0);
        const a = document.createElement('a');
        a.href = canvas.toDataURL('image/png');
        a.download = 'dfd-diagram.png';
        a.click();
      };
      img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
    }

    _getContentBBox() {
      if (this.nodes.length === 0) return { x: 0, y: 0, w: 400, h: 300 };
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (const n of this.nodes) {
        minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
        maxX = Math.max(maxX, n.x + n.width); maxY = Math.max(maxY, n.y + n.height);
      }
      for (const b of this.boundaries) {
        minX = Math.min(minX, b.x); minY = Math.min(minY, b.y);
        maxX = Math.max(maxX, b.x + b.width); maxY = Math.max(maxY, b.y + b.height);
      }
      return { x: minX, y: minY, w: maxX - minX, h: maxY - minY };
    }

    /* ── Minimap ── */
    _buildMinimap() {
      const wrap = document.createElement('div');
      wrap.className = 'dfd-minimap';
      wrap.innerHTML = '<canvas width="200" height="140"></canvas><div class="dfd-minimap-viewport"></div>';
      this._minimapCanvas = wrap.querySelector('canvas');
      this._minimapViewport = wrap.querySelector('.dfd-minimap-viewport');
      // Allow dragging viewport in minimap to pan
      let dragging = false;
      wrap.addEventListener('mousedown', (e) => {
        dragging = true;
        this._minimapPan(e);
      });
      wrap.addEventListener('mousemove', (e) => { if (dragging) this._minimapPan(e); });
      document.addEventListener('mouseup', () => { dragging = false; });
      return wrap;
    }

    _minimapPan(e) {
      const rect = this._minimapCanvas.getBoundingClientRect();
      const mx = (e.clientX - rect.left) / rect.width;
      const my = (e.clientY - rect.top) / rect.height;
      const bbox = this._getContentBBox();
      const targetX = bbox.x + mx * bbox.w - (this._svg.clientWidth / this.zoom) / 2;
      const targetY = bbox.y + my * bbox.h - (this._svg.clientHeight / this.zoom) / 2;
      this.panX = -targetX * this.zoom;
      this.panY = -targetY * this.zoom;
      this._applyTransform();
      this._updateMinimap();
    }

    _updateMinimap() {
      if (!this._minimapCanvas) return;
      const canvas = this._minimapCanvas;
      const ctx = canvas.getContext('2d');
      const cw = canvas.width, ch = canvas.height;
      ctx.clearRect(0, 0, cw, ch);
      ctx.fillStyle = '#1a1a1a';
      ctx.fillRect(0, 0, cw, ch);

      const bbox = this._getContentBBox();
      if (bbox.w === 0 || bbox.h === 0) return;
      const pad = 10;
      const scale = Math.min((cw - pad*2) / bbox.w, (ch - pad*2) / bbox.h);
      const ox = pad + ((cw - pad*2) - bbox.w * scale) / 2 - bbox.x * scale;
      const oy = pad + ((ch - pad*2) - bbox.h * scale) / 2 - bbox.y * scale;

      // Draw boundaries
      ctx.strokeStyle = 'rgba(232,155,58,0.4)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 2]);
      for (const b of this.boundaries) {
        ctx.strokeRect(ox + b.x * scale, oy + b.y * scale, b.width * scale, b.height * scale);
      }
      ctx.setLineDash([]);

      // Draw edges
      ctx.strokeStyle = 'rgba(106,106,106,0.5)';
      ctx.lineWidth = 0.5;
      for (const e of this.edges) {
        const s = this._findNode(e.sourceId);
        const t = this._findNode(e.targetId);
        if (!s || !t) continue;
        ctx.beginPath();
        ctx.moveTo(ox + (s.x + s.width/2) * scale, oy + (s.y + s.height/2) * scale);
        ctx.lineTo(ox + (t.x + t.width/2) * scale, oy + (t.y + t.height/2) * scale);
        ctx.stroke();
      }

      // Draw nodes
      const typeColors = { process: '#3a3a3a', external_entity: '#c4943a', data_store: '#28D07D' };
      for (const n of this.nodes) {
        ctx.fillStyle = typeColors[n.type] || '#3a3a3a';
        ctx.globalAlpha = 0.8;
        ctx.fillRect(ox + n.x * scale, oy + n.y * scale, n.width * scale, n.height * scale);
      }
      ctx.globalAlpha = 1;

      // Draw viewport rectangle
      if (this._svg) {
        const vw = this._svg.clientWidth / this.zoom;
        const vh = this._svg.clientHeight / this.zoom;
        const vx = -this.panX / this.zoom;
        const vy = -this.panY / this.zoom;
        ctx.strokeStyle = '#28D07D';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(ox + vx * scale, oy + vy * scale, vw * scale, vh * scale);
        // Also update the CSS viewport overlay
        if (this._minimapViewport) {
          this._minimapViewport.style.left = (ox + vx * scale) + 'px';
          this._minimapViewport.style.top = (oy + vy * scale) + 'px';
          this._minimapViewport.style.width = (vw * scale) + 'px';
          this._minimapViewport.style.height = (vh * scale) + 'px';
        }
      }
    }

    /* ═══════════════════════════════════
       Load from Analysis Result
       ═══════════════════════════════════ */
    loadFromAnalysisResult(result) {
      this.analysisResult = result;
      this.threats = result.threats || result.threats_final || [];

      // Check if mermaid_dfd is effectively empty (just header, no nodes)
      const mermaidEmpty = !result.mermaid_dfd || result.mermaid_dfd.trim().replace(/^(graph|flowchart)\s+(TD|LR|TB|RL|BT)\s*$/i, '') === '';

      // Build diagram from structured data or mermaid
      if (result.components && result.components.length > 0) {
        this._loadFromStructured(result);
      } else if (!mermaidEmpty) {
        this.fromMermaid(result.mermaid_dfd);
      } else if (this.threats.length > 0) {
        // Fallback: auto-build nodes from threat component data
        this._buildFromThreats();
      }

      // Render threat sidebar
      this._renderThreatList();

      // Update panels
      this._updateMermaidCode();
      this._updateDescription();

      this._showToast(`Cargado: ${this.nodes.length} componentes, ${this.threats.length} amenazas`);
    }

    /**
     * Build DFD nodes from threat component names when no structured data
     * or mermaid is available. Groups threats by component and creates nodes.
     */
    _buildFromThreats() {
      this._saveUndo();
      this.nodes = [];
      this.edges = [];
      this.boundaries = [];

      const componentMap = new Map();
      this.threats.forEach(t => {
        const comp = t.component || t.target_component || 'Sistema';
        if (!componentMap.has(comp)) componentMap.set(comp, []);
        componentMap.get(comp).push(t);
      });

      const colWidth = 200;
      let idx = 0;
      const nodeMap = new Map();
      for (const [compName, threats] of componentMap) {
        const def = NODE_DEFAULTS.process;
        const node = {
          id: uid('n'), type: 'process', label: compName,
          x: 100 + (idx % 4) * colWidth,
          y: 100 + Math.floor(idx / 4) * 120,
          width: def.width, height: def.height,
          scope: 'internal',
          description: `${threats.length} amenaza(s) identificada(s)`,
        };
        this.nodes.push(node);
        nodeMap.set(compName, node);
        idx++;
      }

      // Try to infer edges from threats that mention related components
      const compNames = [...componentMap.keys()];
      this.threats.forEach(t => {
        const src = t.component || t.target_component;
        const desc = ((t.description || '') + ' ' + (t.mitigation || '')).toLowerCase();
        if (!src) return;
        compNames.forEach(other => {
          if (other !== src && desc.includes(other.toLowerCase())) {
            const srcNode = nodeMap.get(src);
            const tgtNode = nodeMap.get(other);
            if (srcNode && tgtNode) {
              // Avoid duplicate edges
              const exists = this.edges.some(e => e.sourceId === srcNode.id && e.targetId === tgtNode.id);
              if (!exists) {
                this.edges.push({
                  id: uid('e'), sourceId: srcNode.id, targetId: tgtNode.id,
                  label: '', protocol: '', dataType: '', bidirectional: false,
                });
              }
            }
          }
        });
      });

      this._autoLayout();
      this._render();
      this.fitToView();
    }

    _loadFromStructured(data) {
      this._saveUndo();
      this.nodes = [];
      this.edges = [];
      this.boundaries = [];

      const nodeMap = new Map();
      const colWidth = 180;
      let y = 100;

      const components = data.components || [];
      components.forEach((c, i) => {
        const def = NODE_DEFAULTS[c.type] || NODE_DEFAULTS.process;
        const node = {
          id: uid('n'), type: c.type || 'process', label: c.name,
          x: 100 + (i % 4) * colWidth, y: y + Math.floor(i / 4) * 100,
          width: def.width, height: def.height,
          scope: c.scope || 'internal', description: c.description || '',
        };
        this.nodes.push(node);
        nodeMap.set(c.name, node);
      });

      const flows = data.data_flows || [];
      for (const f of flows) {
        const src = nodeMap.get(f.source), tgt = nodeMap.get(f.destination);
        if (src && tgt) {
          this.edges.push({
            id: uid('e'), sourceId: src.id, targetId: tgt.id,
            label: f.protocol || '', protocol: f.protocol || '',
            dataType: f.data_type || '', bidirectional: f.bidirectional || false,
          });
        }
      }

      const boundaries = data.trust_boundaries || [];
      boundaries.forEach((tb, i) => {
        const insideNodes = (tb.components_inside || []).map(name => nodeMap.get(name)).filter(Boolean);
        let bx = 80 + i * 300, by = 80, bw = 260, bh = 200;
        if (insideNodes.length > 0) {
          bx = Math.min(...insideNodes.map(n => n.x)) - 20;
          by = Math.min(...insideNodes.map(n => n.y)) - 30;
          bw = Math.max(...insideNodes.map(n => n.x + n.width)) + 20 - bx;
          bh = Math.max(...insideNodes.map(n => n.y + n.height)) + 20 - by;
        }
        this.boundaries.push({ id: uid('b'), label: tb.name, x: bx, y: by, width: bw, height: bh });
      });

      this._autoLayout();
      this._render();
      this.fitToView();
    }

    /* ═══════════════════════════════════
       Utility
       ═══════════════════════════════════ */
    _esc(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    _showToast(msg) {
      this._toast.textContent = msg;
      this._toast.classList.add('visible');
      clearTimeout(this._toastTimeout);
      this._toastTimeout = setTimeout(() => this._toast.classList.remove('visible'), 2500);
    }

    /* ═══════════════════════════════════
       SVG Icons
       ═══════════════════════════════════ */
    _buildIcons() {
      return {
        cursor: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M3 1l10 7-5 1-2 5z"/></svg>`,
        connect: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="4" cy="4" r="2.5"/><circle cx="12" cy="12" r="2.5"/><line x1="6" y1="6" x2="10" y2="10" stroke-dasharray="2 1.5"/></svg>`,
        process: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="2" y="4" width="12" height="8" rx="2"/></svg>`,
        external: `<svg viewBox="0 0 16 16" fill="none" stroke="#c4943a" stroke-width="1.2"><rect x="2" y="4" width="12" height="8" rx="2"/><circle cx="8" cy="2" r="1.2" fill="#c4943a"/></svg>`,
        dataStore: `<svg viewBox="0 0 16 16" fill="none" stroke="#28D07D" stroke-width="1.2"><rect x="2" y="4" width="12" height="8" rx="2"/><line x1="2" y1="7" x2="14" y2="7"/></svg>`,
        boundary: `<svg viewBox="0 0 16 16" fill="none" stroke="#e89b3a" stroke-width="1.2" stroke-dasharray="3 2"><rect x="1" y="1" width="14" height="14" rx="3"/></svg>`,
        undo: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M7 3L3 7l4 4V8c3 0 5 1 6 4 0-5-3-7-6-7V3z"/></svg>`,
        redo: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M9 3l4 4-4 4V8c-3 0-5 1-6 4 0-5 3-7 6-7V3z"/></svg>`,
        trash: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M5 2V1h6v1h3v2H2V2h3zm1 3h1v7H6V5zm3 0h1v7H9V5zM3 4h10l-1 10H4L3 4z"/></svg>`,
        grid: `<svg viewBox="0 0 16 16" fill="currentColor"><circle cx="4" cy="4" r="1.2"/><circle cx="8" cy="4" r="1.2"/><circle cx="12" cy="4" r="1.2"/><circle cx="4" cy="8" r="1.2"/><circle cx="8" cy="8" r="1.2"/><circle cx="12" cy="8" r="1.2"/><circle cx="4" cy="12" r="1.2"/><circle cx="8" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/></svg>`,
        fit: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 5V2h3M11 2h3v3M14 11v3h-3M5 14H2v-3"/></svg>`,
        route: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><polyline points="2,12 2,4 14,4 14,12" fill="none"/><circle cx="2" cy="12" r="1.5" fill="currentColor"/><circle cx="14" cy="12" r="1.5" fill="currentColor"/></svg>`,
        force: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2"><circle cx="8" cy="8" r="3"/><circle cx="3" cy="3" r="1.5"/><circle cx="13" cy="3" r="1.5"/><circle cx="3" cy="13" r="1.5"/><circle cx="13" cy="13" r="1.5"/><line x1="5.8" y1="5.8" x2="4" y2="4"/><line x1="10.2" y1="5.8" x2="12" y2="4"/><line x1="5.8" y1="10.2" x2="4" y2="12"/><line x1="10.2" y1="10.2" x2="12" y2="12"/></svg>`,
        exportSvg: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M2 2v12h12V5l-3-3H2zm8 0v3h3"/><text x="5" y="11" font-size="5" font-weight="bold" fill="#28D07D">SVG</text></svg>`,
        exportPng: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M2 2v12h12V5l-3-3H2zm8 0v3h3"/><text x="4" y="11" font-size="5" font-weight="bold" fill="#58a6ff">PNG</text></svg>`,
      };
    }
  }

  /* ═══════════════════════════════════
     Global API
     ═══════════════════════════════════ */
  window.DFDEditor = DFDEditor;

  let _instance = null;
  window.getDFDEditor = function () {
    if (!_instance) {
      const el = document.getElementById('dfdEditorRoot');
      if (el) _instance = new DFDEditor('dfdEditorRoot');
    }
    return _instance;
  };

  window.initDFDEditor = function () {
    return window.getDFDEditor();
  };

  /**
   * Called from loadResults() after analysis completes.
   * Builds the diagram from the result and populates the threat sidebar.
   */
  window.loadDFDEditorFromResult = function (resultData) {
    const editor = window.getDFDEditor();
    if (editor) {
      editor.loadFromAnalysisResult(resultData);
    }
  };

})();
