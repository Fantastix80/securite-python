from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from svglib.svglib import svg2rlg
from pygal import Config, Bar

class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport de l'analyse réseau"
        self.summary = summary

    def build_pdf(self) -> None:
        """
        Create pdf file
        """
        doc = SimpleDocTemplate(self.filename, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()

        # Title
        story.append(Paragraph(self.title, styles['Title']))
        story.append(Spacer(1, 20))

        # Summary
        story.append(Paragraph(self.summary, styles['BodyText']))
        story.append(Spacer(1, 20))

        # Graph
        self.generate_graph()
        drawing = svg2rlg("graph.svg")
        story.append(drawing)
        story.append(Spacer(1, 20))

        # Table
        table = self.generate_table()
        story.append(Paragraph("Alertes détectées :", styles['Heading2']))
        story.append(table)

        # Build PDF
        doc.build(story)

    def generate_graph(self) -> None:
        """
        Generate graph and array
        """
        config = Config()
        config.legend_at_bottom = True
        config.show_legend = True
        config.print_values = False
        config.width = 500
        config.height = 400

        bar_chart = Bar(config)
        bar_chart.title = 'Nombre de paquets par protocole'
        for protocol, count in self.capture.protocol_counts:
            bar_chart.add(protocol, count)
        bar_chart.render_to_file("graph.svg")

    def generate_table(self) -> Table:
        """
        Generate graph and array
        """
        data = [["Type", "Message"]]
        for alert in self.capture.alerts:
            data.append([alert["type"], alert["message"]])

        table = Table(data, colWidths=[150, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
        ]))

        return table
