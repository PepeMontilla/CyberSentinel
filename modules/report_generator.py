from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
from datetime import datetime

def generate_pdf_report(analysis_data, output_path):
    """
    Genera un reporte PDF profesional con los resultados del análisis.

    Args:
        analysis_data: Diccionario con los datos del análisis
        output_path: Ruta donde guardar el PDF
    """
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Estilos personalizados
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Centrado
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=20,
        textColor=colors.blue
    )

    normal_style = styles['Normal']

    # Título
    story.append(Paragraph("CyberSentinel - Reporte de Análisis Forense", title_style))
    story.append(Spacer(1, 12))

    # Fecha del reporte
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    story.append(Paragraph(f"Fecha del análisis: {fecha}", normal_style))
    story.append(Spacer(1, 20))

    # Información del archivo
    story.append(Paragraph("Información del Archivo Analizado", subtitle_style))

    metadata = analysis_data['metadata']
    metadata_table_data = [
        ['Propiedad', 'Valor'],
        ['Nombre del archivo', metadata['filename']],
        ['Tamaño', f"{metadata['size_bytes'] / 1024:.1f} KB"],
        ['Hash SHA-256', metadata['sha256']]
    ]

    metadata_table = Table(metadata_table_data, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    story.append(metadata_table)
    story.append(Spacer(1, 20))

    # Veredicto de IA
    story.append(Paragraph("Veredicto de Inteligencia Artificial", subtitle_style))

    ai_verdict = analysis_data['ai_verdict']
    verdict_color = colors.green
    if ai_verdict['veredicto'] == 'Malicioso':
        verdict_color = colors.red
    elif ai_verdict['veredicto'] == 'Sospechoso':
        verdict_color = colors.orange

    story.append(Paragraph(f"<b>Veredicto:</b> <font color='{verdict_color}'>{ai_verdict['veredicto']}</font>", normal_style))
    story.append(Paragraph(f"<b>Confianza:</b> {ai_verdict['confianza']}%", normal_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Explicación Técnica:</b>", normal_style))
    story.append(Paragraph(ai_verdict['explicacion_tecnica'], normal_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Recomendaciones:</b>", normal_style))
    story.append(Paragraph(ai_verdict['recomendaciones'], normal_style))
    story.append(Spacer(1, 20))

    # Análisis de Comportamientos
    story.append(Paragraph("Análisis de Comportamientos", subtitle_style))
    story.append(Paragraph(f"Puntuación de Riesgo: {analysis_data['risk_score']} puntos", normal_style))
    story.append(Spacer(1, 12))

    if analysis_data['behaviors']:
        behaviors_data = [['Función', 'DLL', 'Categoría', 'Severidad', 'Descripción']]
        for behavior in analysis_data['behaviors']:
            severity_color = colors.green
            if behavior['severity'] == 'HIGH':
                severity_color = colors.red
            elif behavior['severity'] == 'MEDIUM':
                severity_color = colors.orange
            
            severidad_formateada = Paragraph(
                f"<font color='{severity_color}'><b>{behavior['severity']}</b></font>", 
                normal_style
            )
            behaviors_data.append([
                behavior['function'],
                behavior['dll'],
                behavior['category'],
                severidad_formateada,
                behavior['description']
            ])

        behaviors_table = Table(behaviors_data, colWidths=[1.5*inch, 1.2*inch, 1.2*inch, 1*inch, 2.5*inch])
        behaviors_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))

        story.append(behaviors_table)
    else:
        story.append(Paragraph("No se detectaron comportamientos sospechosos.", normal_style))

    story.append(Spacer(1, 20))

    # Strings Sospechosos
    if analysis_data['strings']:
        story.append(Paragraph("Strings Sospechosos Detectados", subtitle_style))

        strings_text = ""
        for i, string in enumerate(analysis_data['strings'], 1):
            strings_text += f"{i}. {string}\n"

        story.append(Paragraph(strings_text, normal_style))
        story.append(Spacer(1, 20))

    # Pie de página
    story.append(Spacer(1, 30))
    story.append(Paragraph("Reporte generado por CyberSentinel - Análisis Estático Forense", styles['Italic']))
    story.append(Paragraph("Este reporte contiene información técnica confidencial.", styles['Italic']))

    # Generar PDF
    doc.build(story)
    return output_path