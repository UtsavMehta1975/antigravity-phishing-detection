/**
 * Interactive Evidence Graph Canvas Visualizer
 * Renders directed graph provenance chains, critical risk paths, and node inspectors.
 */

export class GraphVisualizer {
  constructor(canvasId, onNodeSelectCallback) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.onNodeSelect = onNodeSelectCallback;

    this.nodes = [];
    this.edges = [];
    this.criticalPath = [];

    this.selectedNode = null;
    this.draggedNode = null;
    this.isDragging = false;
    this.dragOffsetX = 0;
    this.dragOffsetY = 0;

    this.scale = 1.0;
    this.panX = 0;
    this.panY = 0;

    this.animationFrame = null;
    this._initEvents();
    this.resize();
  }

  resize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width || 800;
    this.canvas.height = 480;
    this.render();
  }

  loadGraph(graphData) {
    if (!graphData || !graphData.nodes) {
      this.nodes = [];
      this.edges = [];
      this.render();
      return;
    }

    this.criticalPath = graphData.critical_risk_path || [];

    // Initialize node positions with gentle horizontal layout flow
    const nodeMap = new Map();
    const count = graphData.nodes.length;
    const startX = 80;
    const endX = this.canvas.width - 80;
    const stepX = (endX - startX) / Math.max(1, count - 1);

    this.nodes = graphData.nodes.map((n, i) => {
      const nodeObj = {
        ...n,
        x: startX + i * stepX + (Math.random() - 0.5) * 40,
        y: this.canvas.height / 2 + (Math.random() - 0.5) * 160,
        vx: 0,
        vy: 0,
        radius: 26,
        isCritical: this.criticalPath.includes(n.id)
      };
      nodeMap.set(n.id, nodeObj);
      return nodeObj;
    });

    this.edges = (graphData.edges || []).map(e => ({
      ...e,
      sourceNode: nodeMap.get(e.source),
      targetNode: nodeMap.get(e.target)
    })).filter(e => e.sourceNode && e.targetNode);

    // Run physics simulation briefly to untangle
    this.simulatePhysics(40);
    this.render();
  }

  simulatePhysics(iterations = 30) {
    for (let it = 0; it < iterations; it++) {
      // Repulsion between nodes
      for (let i = 0; i < this.nodes.length; i++) {
        for (let j = i + 1; j < this.nodes.length; j++) {
          const n1 = this.nodes[i];
          const n2 = this.nodes[j];
          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const dist = Math.hypot(dx, dy) || 1;
          if (dist < 180) {
            const force = (180 - dist) / 180 * 4.0;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            n1.x -= fx;
            n1.y -= fy;
            n2.x += fx;
            n2.y += fy;
          }
        }
      }

      // Spring tension along edges
      for (const edge of this.edges) {
        const dx = edge.targetNode.x - edge.sourceNode.x;
        const dy = edge.targetNode.y - edge.sourceNode.y;
        const dist = Math.hypot(dx, dy) || 1;
        const targetDist = 130;
        const force = (dist - targetDist) * 0.05;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        edge.sourceNode.x += fx;
        edge.sourceNode.y += fy;
        edge.targetNode.x -= fx;
        edge.targetNode.y -= fy;
      }

      // Keep within bounds
      for (const n of this.nodes) {
        n.x = Math.max(50, Math.min(this.canvas.width - 50, n.x));
        n.y = Math.max(50, Math.min(this.canvas.height - 50, n.y));
      }
    }
  }

  render() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    // Draw Grid Background
    this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    this.ctx.lineWidth = 1;
    const gridSize = 30;
    for (let x = 0; x < this.canvas.width; x += gridSize) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, this.canvas.height);
      this.ctx.stroke();
    }
    for (let y = 0; y < this.canvas.height; y += gridSize) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(this.canvas.width, y);
      this.ctx.stroke();
    }

    // 1. Draw Edges
    for (const edge of this.edges) {
      const s = edge.sourceNode;
      const t = edge.targetNode;
      const isCriticalEdge = s.isCritical && t.isCritical;

      this.ctx.beginPath();
      this.ctx.moveTo(s.x, s.y);
      this.ctx.lineTo(t.x, t.y);

      if (isCriticalEdge) {
        this.ctx.strokeStyle = '#ff3366';
        this.ctx.lineWidth = 3;
        this.ctx.shadowColor = 'rgba(255, 51, 102, 0.6)';
        this.ctx.shadowBlur = 8;
      } else {
        this.ctx.strokeStyle = 'rgba(79, 172, 254, 0.35)';
        this.ctx.lineWidth = 1.5;
        this.ctx.shadowBlur = 0;
      }
      this.ctx.stroke();
      this.ctx.shadowBlur = 0;

      // Draw Arrow
      const angle = Math.atan2(t.y - s.y, t.x - s.x);
      const arrowX = t.x - Math.cos(angle) * (t.radius + 6);
      const arrowY = t.y - Math.sin(angle) * (t.radius + 6);

      this.ctx.beginPath();
      this.ctx.moveTo(arrowX, arrowY);
      this.ctx.lineTo(
        arrowX - 10 * Math.cos(angle - Math.PI / 6),
        arrowY - 10 * Math.sin(angle - Math.PI / 6)
      );
      this.ctx.lineTo(
        arrowX - 10 * Math.cos(angle + Math.PI / 6),
        arrowY - 10 * Math.sin(angle + Math.PI / 6)
      );
      this.ctx.fillStyle = isCriticalEdge ? '#ff3366' : 'rgba(79, 172, 254, 0.6)';
      this.ctx.fill();

      // Draw Edge Label
      if (edge.relationship) {
        const midX = (s.x + t.x) / 2;
        const midY = (s.y + t.y) / 2;
        this.ctx.font = '9px "JetBrains Mono", monospace';
        this.ctx.fillStyle = isCriticalEdge ? '#ff85a1' : 'rgba(255, 255, 255, 0.45)';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(edge.relationship, midX, midY - 6);
      }
    }

    // 2. Draw Nodes
    for (const node of this.nodes) {
      const isSelected = this.selectedNode && this.selectedNode.id === node.id;
      const color = this.getNodeColor(node);

      this.ctx.save();

      // Outer glow for critical/selected
      if (isSelected || node.isCritical) {
        this.ctx.shadowColor = node.isCritical ? 'rgba(255, 51, 102, 0.7)' : 'rgba(0, 242, 254, 0.7)';
        this.ctx.shadowBlur = 15;
      }

      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = color.fill;
      this.ctx.fill();

      this.ctx.lineWidth = isSelected ? 3 : 2;
      this.ctx.strokeStyle = isSelected ? '#00f2fe' : color.stroke;
      this.ctx.stroke();

      this.ctx.restore();

      // Node Icon / Type Abbreviation
      this.ctx.font = '10px "JetBrains Mono", monospace';
      this.ctx.fillStyle = '#ffffff';
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'middle';
      this.ctx.fillText(this.getNodeBadge(node.type), node.x, node.y - 2);

      // Node Label Text Below
      this.ctx.font = '11px "Inter", sans-serif';
      this.ctx.fillStyle = '#cbd5e1';
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'top';
      const cleanLabel = (node.label || node.id).substring(0, 20);
      this.ctx.fillText(cleanLabel, node.x, node.y + node.radius + 6);
    }
  }

  getNodeBadge(type) {
    switch (type) {
      case 'MESSAGE': return 'MSG';
      case 'ATTACHMENT': return 'ATT';
      case 'QR_CODE': return 'QR';
      case 'LINK': return 'URL';
      case 'REDIRECT_HOP': return 'HOP';
      case 'LANDING_PAGE': return 'DEST';
      case 'REQUESTED_ACTION': return 'ACT';
      default: return 'NODE';
    }
  }

  getNodeColor(node) {
    if (node.risk_score >= 70.0 || (node.attributes && node.attributes.smuggling_detected)) {
      return { fill: 'rgba(255, 51, 102, 0.3)', stroke: '#ff3366' };
    }
    if (node.type === 'LANDING_PAGE' && node.attributes && node.attributes.destination_status === 'UNKNOWN') {
      return { fill: 'rgba(168, 85, 247, 0.35)', stroke: '#a855f7' };
    }
    if (node.risk_score >= 35.0) {
      return { fill: 'rgba(255, 179, 0, 0.3)', stroke: '#ffb300' };
    }
    return { fill: 'rgba(0, 242, 254, 0.2)', stroke: '#00f2fe' };
  }

  _initEvents() {
    this.canvas.addEventListener('mousedown', e => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      // Check if clicked a node
      for (let i = this.nodes.length - 1; i >= 0; i--) {
        const n = this.nodes[i];
        if (Math.hypot(n.x - mouseX, n.y - mouseY) <= n.radius + 6) {
          this.selectedNode = n;
          this.draggedNode = n;
          this.isDragging = true;
          this.dragOffsetX = mouseX - n.x;
          this.dragOffsetY = mouseY - n.y;
          if (this.onNodeSelect) this.onNodeSelect(n);
          this.render();
          return;
        }
      }
    });

    window.addEventListener('mousemove', e => {
      if (!this.isDragging || !this.draggedNode) return;
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      this.draggedNode.x = mouseX - this.dragOffsetX;
      this.draggedNode.y = mouseY - this.dragOffsetY;
      this.render();
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
      this.draggedNode = null;
    });

    window.addEventListener('resize', () => this.resize());
  }
}
