import Testing
import Foundation
@testable import ImportKit
import TestSupport

@Suite("RFC 4180 CSV parsing")
struct CSVParserTests {

    @Test("Escaped double-quotes and commas inside quotes")
    func quotesAndCommas() throws {
        let csv = "a,b\n\"he said \"\"hi\"\"\",\"x,y\"\n"
        let table = try CSVParser.parse(csv)
        #expect(table.headers == ["a", "b"])
        #expect(table.rows.count == 1)
        #expect(table.rows[0][0] == "he said \"hi\"")
        #expect(table.rows[0][1] == "x,y")
    }

    @Test("Newline embedded inside a quoted field is preserved, not a record break")
    func embeddedNewline() throws {
        let csv = "h1,h2\nfield1,\"line1\nline2\"\n"
        let table = try CSVParser.parse(csv)
        #expect(table.rows.count == 1)
        #expect(table.rows[0][0] == "field1")
        #expect(table.rows[0][1] == "line1\nline2")
    }

    @Test("Trailing empty fields are kept; trailing newline doesn't add a row")
    func trailingFields() throws {
        let csv = "a,b,c\n1,2,\n"   // last field empty
        let table = try CSVParser.parse(csv)
        #expect(table.rows.count == 1)
        #expect(table.rows[0] == ["1", "2", ""])
    }

    @Test("CRLF line endings act as record separators")
    func crlf() throws {
        let csv = "a,b\r\n1,2\r\n3,4\r\n"
        let table = try CSVParser.parse(csv)
        #expect(table.headers == ["a", "b"])
        #expect(table.rows == [["1", "2"], ["3", "4"]])
    }

    @Test("UTF-8 BOM is stripped before the header is read")
    func bom() throws {
        let csv = "\u{FEFF}a,b\n1,2\n"
        let table = try CSVParser.parse(csv)
        #expect(table.headers == ["a", "b"])
        #expect(table.rows == [["1", "2"]])
    }

    @Test("Chrome fixture: the quoted note keeps its embedded comma")
    func chromeQuotedNote() throws {
        let table = try CSVParser.parse(try Fixtures.data("chrome.csv"))
        #expect(table.headers == ["name", "url", "username", "password", "note"])
        // Row index 1 is the GitHub sean-work row with the quoted note.
        #expect(table.rows[1][4] == "work account, same password oops")
    }

    @Test("Apple fixture: Vault Notes row has a real embedded newline in Notes")
    func appleEmbeddedNewline() throws {
        let table = try CSVParser.parse(try Fixtures.data("apple_passwords.csv"))
        // Vault Notes is the second data row (index 1).
        #expect(table.rows[1][0] == "Vault Notes")
        #expect(table.rows[1][4] == "first line\nsecond line")
    }
}
