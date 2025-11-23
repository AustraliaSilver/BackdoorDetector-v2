package backdoordetected.services;

import backdoordetected.decompiler.DeobfuscationPipeline;
import backdoordetected.exceptions.DeobfuscationException;
import backdoordetected.utils.StandaloneLogger;
import java.nio.file.Path;
import java.util.logging.Logger;

public class DeobfuscationService {
    private static final Logger logger = StandaloneLogger.getLogger();
    private final DeobfuscationPipeline pipeline;

    public DeobfuscationService() {
        this.pipeline = new DeobfuscationPipeline();
    }

    public Path deobfuscate(Path pluginPath) throws DeobfuscationException {
        try {
            logger.info("Attempting to deobfuscate: " + pluginPath.getFileName());
            Path deobfuscated = pipeline.deobfuscate(pluginPath);

            if (!deobfuscated.equals(pluginPath)) {
                logger.info("Successfully deobfuscated to: " + deobfuscated.getFileName());
                return deobfuscated;
            } else {
                logger.info("Deobfuscation not needed or failed, using original JAR");
                return pluginPath;
            }
        } catch (Exception e) {
            logger.warning("Deobfuscation failed: " + e.getMessage() + ". Continuing with original JAR.");
            return pluginPath;
        }
    }
}
