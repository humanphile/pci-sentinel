//! Local image OCR via the Apple Vision framework (macOS only).
//!
//! The bundled Qwen 2.5 instruct model is text-only and cannot see image
//! pixels. To let the local LLM genuinely evaluate image evidence, we OCR the
//! image on-device with Vision and feed the extracted text into the audit
//! prompt. On platforms without an OCR backend we report an honest result
//! instead of hallucinating about image content.

/// Decode a base64 image payload and extract visible text using Apple Vision.
/// Returns an `Err` if the payload is invalid or no recognizable text was found.
#[cfg(target_os = "macos")]
pub fn extract_text_from_image_base64(image_b64: &str) -> Result<String, String> {
    use base64::Engine;
    use objc2::rc::Retained;
    use objc2::AllocAnyThread;
    use objc2_foundation::{NSArray, NSData, NSDictionary};
    use objc2_vision::{
        VNImageBasedRequest, VNImageRequestHandler, VNRecognizeTextRequest, VNRequest,
    };

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(image_b64.trim())
        .map_err(|e| format!("Failed to decode image payload: {}", e))?;

    let image_data = NSData::with_bytes(&bytes);

    // Generic inference from the `initWithData_options` signature resolves the
    // dictionary element types to `NSDictionary<VNImageOption, AnyObject>`.
    let options = NSDictionary::new();

    let handler = VNImageRequestHandler::initWithData_options(
        VNImageRequestHandler::alloc(),
        &image_data,
        &options,
    );

    // Create the OCR request. We use the synchronous `performRequests` API so
    // no block/completion handler is required.
    let request = VNRecognizeTextRequest::new();
    let requests: Retained<NSArray<VNRequest>> = {
        let intermediate: Retained<VNImageBasedRequest> = request.clone().into_super();
        let as_request: Retained<VNRequest> = intermediate.into_super();
        NSArray::from_retained_slice(&[as_request])
    };

    handler
        .performRequests_error(&requests)
        .map_err(|e| format!("Vision OCR failed: {}", e))?;

    let mut extracted: Vec<String> = Vec::new();
    if let Some(results) = request.results() {
        for observation in results.iter() {
            let candidates = observation.topCandidates(1);
            for candidate in candidates.iter() {
                extracted.push(candidate.string().to_string());
            }
        }
    }

    let trimmed = extracted.join("\n");
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return Err("No recognizable text found in the image.".into());
    }
    Ok(trimmed.to_string())
}

/// Non-macOS fallback: no OCR backend, so report honestly.
#[cfg(not(target_os = "macos"))]
pub fn extract_text_from_image_base64(_image_b64: &str) -> Result<String, String> {
    Err(
        "Image OCR is not available on this platform; attach a readable text version of the artifact."
            .into(),
    )
}
