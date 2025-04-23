def global_qss():
    return """
    QWidget {
        font-family: 'Segoe UI', sans-serif;
        background: #f0f0f0;
    }
    QGroupBox {
        font-size: 14px;
        font-weight: bold;
        color: #333;
        border: 1px solid #bbb;
        border-radius: 5px;
        margin-top: 10px;
        background: #fff;
    }
    QPushButton {
        background-color: #5a9;
        border: none;
        border-radius: 4px;
        padding: 8px 12px;
        color: white;
        font-weight: 600;
    }
    QPushButton:hover {
        background-color: #48a;
    }
    QLineEdit, QTextEdit {
        background: #fff;
        border: 1px solid #ccc;
        border-radius: 3px;
        padding: 4px;
    }
    """
