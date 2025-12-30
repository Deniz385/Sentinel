# tests/test_patterns.py
import pytest
import sys
import os

# src modülünü bulabilmesi için yol tanımlaması
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from patterns import get_patterns

patterns = get_patterns()

def test_email_pattern():
    """E-posta regex'inin doğruluğunu test eder."""
    # Geçerli senaryolar
    assert patterns["EMAIL"].match("deniz.celik@adu.edu.tr")
    assert patterns["EMAIL"].match("test_user123@gmail.com")
    
    # Geçersiz senaryolar
    assert not patterns["EMAIL"].match("deniz.celik@")      # Domain yok
    assert not patterns["EMAIL"].match("deniz@.com")        # Domain adı yok
    assert not patterns["EMAIL"].match("@gmail.com")        # Kullanıcı adı yok

def test_tr_id_pattern():
    """TC Kimlik No benzeri yapıları yakalayıp yakalamadığını test eder."""
    # Regex şu an sadece 11 hane kontrolü yapıyor (Algoritma kontrolü scanner'da olacak)
    assert patterns["TR_ID"].match("12345678901")  # 11 hane
    
    # Geçersizler
    assert not patterns["TR_ID"].match("12345")        # Eksik hane
    assert not patterns["TR_ID"].match("123456789012") # Fazla hane
    assert not patterns["TR_ID"].match("02345678901")  # 0 ile başlamaz (Regex'e \b[1-9] eklemiştik)

def test_credit_card_pattern():
    """Kredi kartı formatlarını test eder."""
    # Tireli, boşluklu ve bitişik formatlar
    assert patterns["CREDIT_CARD"].search("1234-5678-1234-5678")
    assert patterns["CREDIT_CARD"].search("1234 5678 1234 5678")
    assert patterns["CREDIT_CARD"].search("1234567812345678")

    # Geçersiz
    assert not patterns["CREDIT_CARD"].search("123-456") # Çok kısa

def test_phone_pattern():
    """Telefon numarası formatlarını test eder."""
    assert patterns["PHONE"].match("0555 123 45 67")
    assert patterns["PHONE"].match("+905551234567")
    assert patterns["PHONE"].match("5551234567")