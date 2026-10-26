import Foundation
import Vision

/// On-device OCR with the Vision framework. Runs at capture time so image text
/// is searchable immediately.
public enum OCRService {

    public static func recognizeText(in imageData: Data) async -> String {
        await Task.detached(priority: .utility) {
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.usesLanguageCorrection = true
            if #available(macOS 13.0, *) {
                request.automaticallyDetectsLanguage = true
            }

            let handler = VNImageRequestHandler(data: imageData, options: [:])
            do {
                try handler.perform([request])
            } catch {
                return ""
            }

            let lines = (request.results ?? []).compactMap {
                $0.topCandidates(1).first?.string
            }
            return lines
                .joined(separator: "\n")
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }.value
    }
}
